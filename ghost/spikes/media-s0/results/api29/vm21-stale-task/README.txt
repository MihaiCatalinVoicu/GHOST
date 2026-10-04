V-M21, API 29, 2026-10-04 00:03-00:22: the run in which a DocumentsUI instance left in the probe's task
by an earlier run received the pick (ui-1/ui-2: that stale DocumentsUI; tap 2 picked; ui-3: the launcher,
the result went to a dead requester; the probe never got it and was force-stopped). DocumentsUI still
recorded the pick (changed/: lastAccess.db, pickCountRecord.db) and the usage-stats files changed in this
19-minute window (changed/data__system__usagestats__*). Kept for the method trap described in the evidence
document, section 21; the screenshots of the other 37 attempts were not kept (0.6 MB each).
