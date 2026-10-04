package org.ghost.messaging.channel.store

import org.ghost.storage.chBytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `ch_join`, `ch_join_request`, `ch_kp_seen` ([JoinStore]); `ch_invite_issued`, `ch_invite_own`, `ch_sponsor`
 * ([InviteStore]); `ch_member_seen`, `ch_member_refresh`, `ch_request`, `ch_box_key` ([MemberStore]) — Phase 10
 * design §6.2, §6.6, §6.7, §8.5, §9, §19.17, §19.29 (slice S3): the rows of admission, each read with the expiry
 * filter of its table, the voiding of CO-5, the bounds as typed errors.
 */
class JoinInviteMemberStoreTest {

    private val today = 20_000L

    private fun inv(i: Int) = chBytes(16, 0x20 + i)
    private fun key(i: Int) = chBytes(32, 0x30 + i)

    // ----------------------------------------------------------------------------------- joins

    @Test
    fun aJoinIsReadByItsKeyPackageRefUntilItsDayAndItsRowsGoWhenTheWelcomeComes() = StoreWorld().use { w ->
        w.channel()
        w.tx { w.stores.joins.insertJoin(it, w.ch, key(1), JoinType.JOIN, inv(1), 0, 20_007) }
        w.tx { w.stores.joins.insertJoin(it, w.ch, key(2), JoinType.REJOIN, null, 1, 20_007) }
        w.tx { w.stores.joins.insertJoin(it, w.ch, key(3), JoinType.RESTORE, inv(3), 0, 19_999) }
        assertEquals(listOf(JoinType.JOIN, JoinType.REJOIN), w.stores.joins.joins(w.db, w.ch, today).map { it.type }.sortedBy { it.ordinal })
        val join = w.stores.joins.join(w.db, w.ch, key(1), today)!!
        assertArrayEquals(inv(1), join.inviteId)
        assertEquals(20_007L, join.expiryDay)
        assertNull(w.stores.joins.join(w.db, w.ch, key(2), today)!!.inviteId)
        assertNull("an expired join is not offered even before the sweep", w.stores.joins.join(w.db, w.ch, key(3), today))
        assertEquals(listOf(key(3).toList()), w.stores.joins.expiredJoins(w.db, today, 10).map { it.kpRef.toList() })
        assertTrue(w.tx { w.stores.joins.deleteJoin(it, w.ch, key(1)) })
        assertEquals(2, w.tx { w.stores.joins.deleteJoins(it, w.ch) })
        assertRedacted(join, key(1), inv(1), w.ch)
    }

    @Test
    fun aRejoinCarriesNoInviteAndAJoinAndARestoreCarryOne() = StoreWorld().use { w ->
        w.channel()
        fun refused(block: () -> Unit) = assertEquals(ChannelStoreError.BAD_VALUE, assertThrows(ChannelStoreException::class.java) { block() }.error)
        refused { w.tx { w.stores.joins.insertJoin(it, w.ch, key(1), JoinType.REJOIN, inv(1), 0, 20_007) } }
        refused { w.tx { w.stores.joins.insertJoin(it, w.ch, key(1), JoinType.JOIN, null, 0, 20_007) } }
        refused { w.tx { w.stores.joins.insertJoin(it, w.ch, key(1), JoinType.RESTORE, null, 0, 20_007) } }
        refused { w.tx { w.stores.joins.insertRequest(it, w.ch, key(1), 0, JoinType.REJOIN, inv(1), chBytes(500, 1), 20_007) } }
        refused { w.tx { w.stores.joins.insertRequest(it, w.ch, key(1), 0, JoinType.JOIN, null, chBytes(500, 1), 20_007) } }
        assertEquals(ChannelStoreError.ROW_EXISTS, assertThrows(ChannelStoreException::class.java) {
            w.tx {
                w.stores.joins.insertJoin(it, w.ch, key(1), JoinType.JOIN, inv(1), 0, 20_007)
                w.stores.joins.insertJoin(it, w.ch, key(1), JoinType.JOIN, inv(1), 0, 20_007)
            }
        }.error)
        assertEquals("the transaction that met the error wrote nothing", 0L, w.count("ch_join"))
    }

    @Test
    fun theRequestsOfAChannelAreInArrivalOrderUntilTheirDayAndAtMostSixtyFour() = StoreWorld().use { w ->
        w.channel()
        w.tx { w.stores.joins.insertRequest(it, w.ch, key(3), 0, JoinType.JOIN, inv(3), chBytes(500, 3), 20_009) }
        w.tx { w.stores.joins.insertRequest(it, w.ch, key(1), 0, JoinType.JOIN, inv(1), chBytes(500, 1), 20_007) }
        w.tx { w.stores.joins.insertRequest(it, w.ch, key(2), 0, JoinType.REJOIN, null, chBytes(500, 2), 20_007) }
        w.tx { w.stores.joins.insertRequest(it, w.ch, key(4), 0, JoinType.JOIN, inv(4), chBytes(500, 4), 19_999) }
        // §6.2.3's "in arrival order": the order of insertion, whatever the hashes and the days (3, 1, 2 here)
        assertEquals(listOf(key(3), key(1), key(2)).map { it.toList() }, w.stores.joins.requests(w.db, w.ch, today).map { it.hash.toList() })
        assertNull(w.stores.joins.request(w.db, w.ch, key(4), today))
        assertEquals(JoinType.REJOIN, w.stores.joins.request(w.db, w.ch, key(2), today)!!.type)
        assertEquals(listOf(key(4).toList()), w.stores.joins.expiredRequests(w.db, today, 10).map { it.hash.toList() })
        // an invite consumed: every other request that names it is dropped
        w.tx { w.stores.joins.insertRequest(it, w.ch, key(5), 0, JoinType.RESTORE, inv(1), chBytes(500, 5), 20_008) }
        assertEquals(2, w.tx { w.stores.joins.deleteRequestsOfInvite(it, w.ch, inv(1)) })
        assertTrue(w.tx { w.stores.joins.deleteRequest(it, w.ch, key(2)) })
        assertFalse(w.tx { w.stores.joins.deleteRequest(it, w.ch, key(2)) })
        // two rows are left (one of them expired and not yet swept: the bound counts it, as the trigger does)
        for (i in 0 until 62) {
            w.tx { w.stores.joins.insertRequest(it, w.ch, ByteArray(32).also { b -> b[0] = 0x55; b[1] = i.toByte() }, 0, JoinType.JOIN, inv(1), chBytes(500, 1), 20_007) }
        }
        assertEquals(64L, w.count("ch_join_request"))
        assertEquals(ChannelStoreError.LIMIT, assertThrows(ChannelStoreException::class.java) {
            w.tx { w.stores.joins.insertRequest(it, w.ch, key(9), 0, JoinType.JOIN, inv(1), chBytes(500, 1), 20_007) }
        }.error)
    }

    @Test
    fun aKeyPackageTagIsRecordedOnceReadWhileItsDayLastsAndBoundedAtOneThousandAndTwentyFour() = StoreWorld().use { w ->
        w.channel()
        val tag = chBytes(16, 5)
        assertFalse(w.stores.joins.isKpSeen(w.db, w.ch, tag, today))
        assertTrue(w.tx { w.stores.joins.markKpSeen(it, w.ch, tag, 20_011) })
        assertFalse(w.tx { w.stores.joins.markKpSeen(it, w.ch, tag, 20_011) })
        assertTrue(w.stores.joins.isKpSeen(w.db, w.ch, tag, 20_011))
        assertFalse("past its day the tag is no evidence", w.stores.joins.isKpSeen(w.db, w.ch, tag, 20_012))
        w.db.transaction {
            for (i in 1 until 1024) {
                w.db.exec("INSERT INTO ch_kp_seen(channel_id, tag, until_day) VALUES (?, ?, 20011)", listOf(w.ch, ByteArray(16).also { b -> b[0] = (i / 256).toByte(); b[1] = (i % 256).toByte(); b[15] = 9 }))
            }
        }
        assertEquals(1024L, w.count("ch_kp_seen"))
        assertEquals(ChannelStoreError.LIMIT, assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.joins.markKpSeen(it, w.ch, chBytes(16, 0x7F), 20_011) } }.error)
        assertFalse("a tag that is there is no new row, so the bound does not apply", w.tx { w.stores.joins.markKpSeen(it, w.ch, tag, 20_011) })
        assertEquals(1024, w.tx { w.stores.joins.deleteKpTags(it, 20_012) })
        assertEquals(0L, w.count("ch_kp_seen"))
    }

    // ---------------------------------------------------------------------------------- invites

    private fun InviteStore.issue(
        w: StoreWorld,
        i: Int,
        sponsor: Int = 1,
        digest: Int = 7,
        pw: Int? = null,
        expiry: Long = 20_007,
    ) = w.tx { insertIssued(it, w.ch, inv(i), key(40 + i), key(sponsor), chBytes(64, 9), chBytes(32, digest), pw, expiry) }

    @Test
    fun anIssuedInviteIsReadUntilItsDayAndTheSweepNamesTheExpiredOnes() = StoreWorld().use { w ->
        w.channel()
        w.stores.invites.issue(w, 1)
        w.stores.invites.issue(w, 2, expiry = 19_999)
        w.stores.invites.issue(w, 3, pw = 2)
        val row = w.stores.invites.issued(w.db, w.ch, inv(1), today)!!
        assertFalse(row.consumed || row.void)
        assertNull(row.pwVersion)
        assertEquals(2, w.stores.invites.issued(w.db, w.ch, inv(3), today)!!.pwVersion)
        assertNull(w.stores.invites.issued(w.db, w.ch, inv(2), today))
        assertEquals(listOf(inv(1).toList(), inv(3).toList()), w.stores.invites.issuedOf(w.db, w.ch, today).map { it.inviteId.toList() })
        assertEquals(0, w.stores.invites.issuedOf(w.db, w.ch, 20_008).size)
        assertEquals(listOf(inv(2).toList()), w.stores.invites.expiredIssued(w.db, today, 10).map { it.inviteId.toList() })
        assertEquals(ChannelStoreError.ROW_EXISTS, assertThrows(ChannelStoreException::class.java) { w.stores.invites.issue(w, 1) }.error)
        assertEquals(ChannelStoreError.BAD_VALUE, assertThrows(ChannelStoreException::class.java) { w.stores.invites.issue(w, 4, pw = 0) }.error)
        assertTrue(w.tx { w.stores.invites.deleteIssued(it, w.ch, inv(2)) })
        assertRedacted(row, key(41), key(1), chBytes(64, 9), chBytes(32, 7), w.ch)
    }

    @Test
    fun aSettleVoidsTheInvitesThatNameTheOldCommittersTheOldPasswordOrARemovedSponsor() = StoreWorld().use { w ->
        w.channel()
        w.stores.invites.issue(w, 1, digest = 7)                // the current committers
        w.stores.invites.issue(w, 2, digest = 8)                // the old committers
        w.stores.invites.issue(w, 3, digest = 7, pw = 1)        // password version 1
        w.stores.invites.issue(w, 4, digest = 7, pw = 2)        // password version 2
        w.stores.invites.issue(w, 5, digest = 7, sponsor = 9)   // a sponsor that is removed
        w.stores.invites.issue(w, 6, digest = 8)                // consumed before the change: nothing to void
        assertTrue(w.tx { w.stores.invites.markConsumed(it, w.ch, inv(6)) })
        assertFalse("consumed once", w.tx { w.stores.invites.markConsumed(it, w.ch, inv(6)) })
        fun voidSet() = w.stores.invites.issuedOf(w.db, w.ch, today).filter { it.void }.map { it.inviteId[0].toInt() - 0x20 }.sorted()
        assertEquals(1, w.tx { w.stores.invites.voidByDigest(it, w.ch, chBytes(32, 7)) })
        assertEquals(listOf(2), voidSet())
        // the password moved to version 2: version 1 is void, the open ones only when the channel became a password channel
        assertEquals(1, w.tx { w.stores.invites.voidByPassword(it, w.ch, 2, includeOpen = false) })
        assertEquals(listOf(2, 3), voidSet())
        assertEquals(2, w.tx { w.stores.invites.voidByPassword(it, w.ch, 2, includeOpen = true) })
        assertEquals(listOf(1, 2, 3, 5), voidSet())
        w.stores.invites.issue(w, 7, digest = 7, sponsor = 9)
        assertEquals(1, w.tx { w.stores.invites.voidOfSponsor(it, w.ch, key(9)) })
        assertEquals(listOf(1, 2, 3, 5, 7), voidSet())
        // a void invite is void once, and a consumed one is never voided
        assertEquals(0, w.tx { w.stores.invites.voidByDigest(it, w.ch, chBytes(32, 7)) })
        assertEquals(false, w.stores.invites.issued(w.db, w.ch, inv(6), today)!!.void)
        assertEquals(true, w.stores.invites.issued(w.db, w.ch, inv(6), today)!!.consumed)
        assertEquals(ChannelStoreError.BAD_VALUE, assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.invites.voidByPassword(it, w.ch, 0, false) } }.error)
    }

    @Test
    fun theSponsorsOwnLinkIsKeptUntilItsDayAndAPasswordInviteIsNeverKept() = StoreWorld().use { w ->
        w.channel()
        w.tx { w.stores.invites.insertOwn(it, inv(1), w.ch, chBytes(363, 1), 20_007) }
        w.tx { w.stores.invites.insertOwn(it, inv(2), w.ch, null, 20_007) }
        w.tx { w.stores.invites.insertOwn(it, inv(3), w.ch, chBytes(363, 3), 19_999) }
        assertEquals(listOf(inv(1).toList(), inv(2).toList()), w.stores.invites.ownInvites(w.db, w.ch, today).map { it.inviteId.toList() })
        assertArrayEquals(chBytes(363, 1), w.stores.invites.ownInvite(w.db, inv(1), today)!!.inviteEnv)
        assertNull("a password invite's link is not at rest (Q50 (a))", w.stores.invites.ownInvite(w.db, inv(2), today)!!.inviteEnv)
        assertNull(w.stores.invites.ownInvite(w.db, inv(3), today))
        assertEquals(listOf(inv(3).toList()), w.stores.invites.expiredOwn(w.db, today, 10).map { it.inviteId.toList() })
        assertEquals(1, w.tx { w.stores.invites.deleteExpiredOwn(it, today) })
        assertEquals(2L, w.count("ch_invite_own"))
        assertEquals(ChannelStoreError.ROW_EXISTS, assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.invites.insertOwn(it, inv(1), w.ch, null, 20_007) } }.error)
        assertRedacted(w.stores.invites.ownInvite(w.db, inv(1), today)!!, chBytes(363, 1), inv(1), w.ch)
    }

    @Test
    fun aMembersAdmissionIsAttributedOnceAndForgottenAtItsRemoval() = StoreWorld().use { w ->
        w.channel()
        assertTrue(w.tx { w.stores.invites.putSponsor(it, w.ch, key(1), key(2), inv(1), 20_000) })
        assertFalse("a rejoin keeps the first record", w.tx { w.stores.invites.putSponsor(it, w.ch, key(1), key(3), inv(2), 20_050) })
        val row = w.stores.invites.sponsor(w.db, w.ch, key(1))!!
        assertArrayEquals(key(2), row.sponsor)
        assertEquals(20_000L, row.admittedDay)
        w.tx { w.stores.invites.putSponsor(it, w.ch, key(4), key(2), inv(1), 20_001) }
        assertEquals(2, w.stores.invites.sponsors(w.db, w.ch).size)
        assertTrue(w.tx { w.stores.invites.deleteSponsor(it, w.ch, key(1)) })
        assertNull(w.stores.invites.sponsor(w.db, w.ch, key(1)))
        assertRedacted(row, key(1), key(2), inv(1), w.ch)
    }

    // ----------------------------------------------------------------------------------- members

    @Test
    fun theLastEpochOfAMemberOnlyGrowsAndTheRefreshDayFindsTheIdle() = StoreWorld().use { w ->
        w.channel()
        w.tx { w.stores.members.noteMemberSeen(it, w.ch, key(1), 5) }
        w.tx { w.stores.members.noteMemberSeen(it, w.ch, key(1), 3) }
        assertEquals(5L, w.stores.members.lastEpoch(w.db, w.ch, key(1)))
        w.tx { w.stores.members.noteMemberSeen(it, w.ch, key(1), 9) }
        assertEquals(9L, w.stores.members.lastEpoch(w.db, w.ch, key(1)))
        assertEquals(1L, w.count("ch_member_seen"))
        assertTrue(w.tx { w.stores.members.deleteMemberSeen(it, w.ch, key(1)) })
        assertNull(w.stores.members.lastEpoch(w.db, w.ch, key(1)))
        w.tx { w.stores.members.putRefresh(it, w.ch, key(1), 19_900) }
        w.tx { w.stores.members.putRefresh(it, w.ch, key(2), 19_950) }
        w.tx { w.stores.members.putRefresh(it, w.ch, key(3), 19_990) }
        w.tx { w.stores.members.putRefresh(it, w.ch, key(1), 19_980) }
        assertEquals(19_980L, w.stores.members.refreshDay(w.db, w.ch, key(1)))
        assertEquals(listOf(key(2).toList()), w.stores.members.idleBefore(w.db, w.ch, 19_960, 10).map { it.toList() })
        assertEquals(listOf(key(2).toList(), key(1).toList()), w.stores.members.idleBefore(w.db, w.ch, 19_985, 10).map { it.toList() })
        assertEquals(1, w.stores.members.idleBefore(w.db, w.ch, 19_985, 1).size)
        assertTrue(w.tx { w.stores.members.deleteRefresh(it, w.ch, key(2)) })
        assertEquals(2L, w.count("ch_member_refresh"))
    }

    @Test
    fun aCommittersPendingWorkIsRecordedOnceReadUntilItsDayAndDroppedAfterIt() = StoreWorld().use { w ->
        w.channel()
        assertTrue(w.tx { w.stores.members.record(it, w.ch, RequestKind.LEAVE, key(1), null, 20_007) })
        assertFalse("the first record stands (what CO-8's work-age rule measures is F-11, not this day)", w.tx { w.stores.members.record(it, w.ch, RequestKind.LEAVE, key(1), null, 20_050) })
        assertEquals(20_007L, w.stores.members.request(w.db, w.ch, RequestKind.LEAVE, key(1), today)!!.untilDay)
        assertTrue(w.tx { w.stores.members.record(it, w.ch, RequestKind.POLICY, byteArrayOf(0), chBytes(100, 2), 20_010) })
        assertTrue(w.tx { w.stores.members.record(it, w.ch, RequestKind.REMOVE, key(2), null, 19_999) })
        assertEquals(listOf(RequestKind.LEAVE, RequestKind.POLICY), w.stores.members.requests(w.db, w.ch, today).map { it.kind })
        assertNull(w.stores.members.request(w.db, w.ch, RequestKind.REMOVE, key(2), today))
        assertEquals(listOf(RequestKind.REMOVE), w.stores.members.expiredRequests(w.db, today, 10).map { it.kind })
        assertTrue(w.tx { w.stores.members.deleteRequest(it, w.ch, RequestKind.LEAVE, key(1)) })
        assertFalse(w.tx { w.stores.members.deleteRequest(it, w.ch, RequestKind.LEAVE, key(1)) })
        assertEquals(ChannelStoreError.BAD_VALUE, assertThrows(ChannelStoreException::class.java) {
            w.tx { w.stores.members.record(it, w.ch, RequestKind.POLICY, ByteArray(0), null, 20_010) }
        }.error)
    }

    @Test
    fun theBoxKeysOfAMemberAreCurrentUntilANewLeafReplacesThemAndGoWhenTheirEpochLeavesRetention() = StoreWorld().use { w ->
        w.channel()
        // the epochs the retention of a retired key is read from: 4 (final, kept through tomorrow) and 5 (open)
        for (e in 4L..5L) w.tx { w.stores.epochs.insert(it, w.ch, e, chBytes(68, 1), chBytes(32, 1)) }
        assertTrue(w.tx { w.stores.epochs.finalize(it, w.ch, 4, null, today - 1, today + 1) })
        w.tx { w.stores.members.insertBoxKey(it, w.ch, key(1), chBytes(60, 1)) }
        assertArrayEquals(key(1), w.stores.members.currentBoxKey(w.db, w.ch)!!.boxPk)
        // a new leaf: its key is inserted, the old one retired in the epoch that replaced it
        w.tx { w.stores.members.insertBoxKey(it, w.ch, key(2), chBytes(60, 2)) }
        assertTrue(w.tx { w.stores.members.retireBoxKey(it, w.ch, key(1), 4) })
        assertFalse(w.tx { w.stores.members.retireBoxKey(it, w.ch, key(1), 5) })
        assertArrayEquals(key(2), w.stores.members.currentBoxKey(w.db, w.ch)!!.boxPk)
        assertEquals(listOf(key(2), key(1)).map { it.toList() }, w.stores.members.boxKeys(w.db, w.ch, today).map { it.boxPk.toList() })
        assertEquals(4L, w.stores.members.boxKey(w.db, w.ch, key(1), today)!!.lastEpoch)
        assertEquals(0, w.tx { w.stores.members.deleteRetiredBefore(it, w.ch, 4) })
        // A retired key is offered only while its last epoch is within retention, whether or not the sweep has
        // deleted it: epoch 4 passes its bound, the oldest retained epoch is 5, and the key replaced in 4 is gone
        // from every read while its row is still there (the review of S3: the reads had no term at all).
        w.db.exec("UPDATE ch_epoch SET keep_until_day = ? WHERE epoch = 4", listOf(today - 1))
        assertNull(w.stores.members.boxKey(w.db, w.ch, key(1), today))
        assertEquals(listOf(key(2).toList()), w.stores.members.boxKeys(w.db, w.ch, today).map { it.boxPk.toList() })
        assertEquals(2L, w.count("ch_box_key"))
        assertArrayEquals("the current leaf's key has no bound", key(2), w.stores.members.currentBoxKey(w.db, w.ch)!!.boxPk)
        assertEquals(1, w.tx { w.stores.members.deleteRetiredBefore(it, w.ch, 5) })
        assertNull(w.stores.members.boxKey(w.db, w.ch, key(1), today))
        assertArrayEquals("the current leaf's key is never deleted", key(2), w.stores.members.currentBoxKey(w.db, w.ch)!!.boxPk)
        // 18 per channel
        for (i in 3 until 19) w.tx { w.stores.members.insertBoxKey(it, w.ch, key(i), chBytes(60, i)) }
        assertEquals(17L, w.count("ch_box_key"))
        w.tx { w.stores.members.insertBoxKey(it, w.ch, key(30), chBytes(60, 30)) }
        assertEquals(ChannelStoreError.LIMIT, assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.members.insertBoxKey(it, w.ch, key(31), chBytes(60, 31)) } }.error)
        w.db.exec("DELETE FROM ch_box_key WHERE box_pk = ?", listOf(key(30)))
        assertEquals(17L, w.count("ch_box_key"))
        assertEquals(ChannelStoreError.ROW_EXISTS, assertThrows(ChannelStoreException::class.java) {
            w.tx { w.stores.members.insertBoxKey(it, w.ch, key(2), chBytes(60, 2)) }
        }.error)
        assertRedacted(w.stores.members.boxKey(w.db, w.ch, key(2), today)!!, key(2), chBytes(60, 2), w.ch)
    }
}
