# Shared lexer for the gates that read Kotlin, Java and Rust sources as text (Phase 9 design §22.33
# item 16: the evasion review of the S0′ gates). Loaded with `require`; defines functions, no side
# effects.
#
# **Why it exists.** A gate that greps one physical line at a time is evaded by anything a developer
# can wrap across a newline — `catch (` on one line and its type on the next, `suspend` and `fun` on
# two lines, a qualified name as `java` / `.net` / `.Socket`, a comment between two tokens
# (`java/**/.net`), Kotlin's backtick quoting (`` `java`.`net` ``). The gates that use this file scan
# a whole file as **one string** with patterns that allow any whitespace, newlines included, between
# tokens, over a view of the source in which what is not code is blanked.
#
#   views($text, $lang)  -> ($with_strings, $code_only). $lang is `kotlin`, `java` or `rust`.
#       Both views have exactly the length and the newlines of $text, so an offset in either is the
#       offset in the file and `line_of` gives the file's line. In both, every comment is blanked
#       (each character but a newline becomes a space; Kotlin and Rust block comments nest, Java's
#       do not) and a Kotlin backtick quoting an identifier becomes a space (`` `java` `` reads as
#       `java`). `$with_strings` keeps string and character literals as written — a package named
#       inside a string (`Class.forName("java.net.Socket")`) is still a reference; `$code_only`
#       blanks their contents too and keeps their delimiters, for rules about keywords and calls.
#       Kotlin string templates (`${…}`) are code in both views, nested strings included. A Java
#       source's `\uXXXX` escapes are decoded first (Java decodes them before it lexes anything).
#   string_literals($text, $lang) -> every string literal as [line of its body, body], in order;
#       a Kotlin template's text stays in the body (`pre ${x} post`), its nested literals follow.
#   line_of(\$text, $offset) -> the 1-based line of $offset.
#   read_text($path)          -> the file's text, CRLF read as LF.
#   squash($s)                -> $s with every run of whitespace, newlines included, one space.
#
# What this is not: a parser. It decides only what is a comment, a string, a character literal and
# a backtick; each gate says what its patterns do not see.
use strict;
use warnings;

sub read_text {
    my ($path) = @_;
    open(my $fh, '<', $path) or die "cannot read $path: $!\n";
    local $/;
    my $text = <$fh>;
    close $fh;
    $text = '' unless defined $text;
    $text =~ s/\r\n/\n/g;
    return $text;
}

sub squash {
    my ($s) = @_;
    $s =~ s/\s+/ /g;
    $s =~ s/^ | $//g;
    return $s;
}

# Every character but a newline as a space.
sub _blank {
    my ($s) = @_;
    $s =~ tr/\n/ /c;
    return $s;
}

sub line_of {
    my ($text_ref, $offset) = @_;
    my $n = () = substr($$text_ref, 0, $offset) =~ /\n/g;
    return $n + 1;
}

our $COLLECT = 0;
our @LITERALS;

sub string_literals {
    my ($text, $lang) = @_;
    local $COLLECT = 1;
    local @LITERALS = ();
    my ($w) = views($text, $lang);
    return map { [line_of(\$w, $_->[0]), $_->[1]] } @LITERALS;
}

sub views {
    my ($text, $lang) = @_;
    die "views: unknown language $lang\n" unless $lang =~ /^(kotlin|java|rust)$/;
    if ($lang eq 'java') {
        # JLS 3.3: a backslash preceded by an even number of backslashes starts a Unicode escape.
        $text =~ s/(?<!\\)((?:\\\\)*)\\u+([0-9A-Fa-f]{4})/$1 . chr(hex($2))/ge;
    }
    my ($w, $c) = ('', '');
    pos($text) = 0;
    _code(\$text, $lang, \$w, \$c, 0);
    return ($w, $c);
}

# Appends $s to both views: code, or a literal's delimiters.
sub _both { my ($w, $c, $s) = @_; $$w .= $s; $$c .= $s; }
# A literal's body: kept in the first view, blanked in the second.
sub _body { my ($w, $c, $s) = @_; $$w .= $s; $$c .= _blank($s); }
# A comment or a quoting backtick: blanked in both.
sub _gone { my ($w, $c, $s) = @_; my $b = _blank($s); $$w .= $b; $$c .= $b; }

# Code from pos($$t) to the end of the text or, inside a Kotlin template (`$in_template`), to the
# `}` that closes it (consumed and appended).
my $FAST_KT = qr/\G([^\/"'`{}]+)/;
# Rust: identifiers whole, so only an `r`, `br`, `cr`, `b` or `c` right before a quote or `#` stops
# the run (a raw, byte or C string prefix, or a raw identifier `r#type`).
my $FAST_RS = qr/\G((?:[^\/"'`{}A-Za-z_]|[A-Za-z_][A-Za-z0-9_]*+(?![A-Za-z0-9_"#']))+)/;

sub _code {
    my ($t, $lang, $w, $c, $in_template) = @_;
    my $depth = 0;
    my $nest = $lang ne 'java';
    my $fast = $lang eq 'rust' ? $FAST_RS : $FAST_KT;
    while (pos($$t) < length $$t) {
        if ($$t =~ /$fast/gc) { _both($w, $c, $1); next; }
        if ($$t =~ /\G(\/\/[^\n]*)/gc) { _gone($w, $c, $1); next; }
        if ($$t =~ /\G\/\*/gc) {
            my $start = pos($$t) - 2;
            my $d = 1;
            while ($d > 0 && pos($$t) < length $$t) {
                if ($nest && $$t =~ /\G\/\*/gc) { $d++; next; }
                if ($$t =~ /\G\*\//gc) { $d--; next; }
                $$t =~ /\G[^*\/]+|\G./gcs;
            }
            _gone($w, $c, substr($$t, $start, pos($$t) - $start));
            next;
        }
        if ($lang eq 'rust' && $$t =~ /\G(?<![A-Za-z0-9_])((?:b|c)?r(#*)")/gc) {
            my ($open, $hashes) = ($1, $2);
            _both($w, $c, $open);
            my $close = '"' . $hashes;
            my $at = index($$t, $close, pos($$t));
            $at = length $$t if $at < 0;
            _body($w, $c, substr($$t, pos($$t), $at - pos($$t)));
            pos($$t) = $at;
            if ($at < length $$t) { _both($w, $c, $close); pos($$t) = $at + length $close; }
            next;
        }
        if ($lang eq 'rust' && $$t =~ /\G(?<![A-Za-z0-9_])([bc])(?=["'])/gc) { _both($w, $c, $1); next; }
        if ($$t =~ /\G"""/gc) {
            _both($w, $c, '"""');
            _literal($t, $lang, $w, $c, 1);
            next;
        }
        if ($$t =~ /\G"/gc) {
            _both($w, $c, '"');
            _literal($t, $lang, $w, $c, 0);
            next;
        }
        if ($$t =~ /\G'/gc) {
            # A character literal is one character or one escape between quotes; anything else after
            # a quote is a Rust lifetime or label (`'a`, `'outer:`), which is code.
            if ($$t =~ /\G((?:\\(?:u\{[0-9A-Fa-f]{1,6}\}|u[0-9A-Fa-f]{4}|x[0-9A-Fa-f]{2}|[0-7]{1,3}|.)|[^'\\\n]))'/gc) {
                _both($w, $c, "'");
                _body($w, $c, $1);
                _both($w, $c, "'");
            } else {
                _both($w, $c, "'");
            }
            next;
        }
        if ($$t =~ /\G`/gc) {
            if ($lang eq 'kotlin' && $$t =~ /\G([^`\n]*)`/gc) {
                _gone($w, $c, '`');
                _both($w, $c, $1);
                _gone($w, $c, '`');
            } else {
                _both($w, $c, '`');
            }
            next;
        }
        if ($$t =~ /\G\{/gc) { $depth++; _both($w, $c, '{'); next; }
        if ($$t =~ /\G\}/gc) {
            if ($in_template && $depth == 0) { _both($w, $c, '}'); return; }
            $depth-- if $depth > 0;
            _both($w, $c, '}');
            next;
        }
        # A lone `/`, or a Rust identifier the fast path stopped at, one character at a time.
        $$t =~ /\G(.)/gcs;
        _both($w, $c, $1);
    }
}

# A string literal after its opening quote(s); records its body when string_literals asked.
sub _literal {
    my ($t, $lang, $w, $c, $raw) = @_;
    my $from = length $$w;
    my $slot;
    if ($COLLECT) { push @LITERALS, [$from, '']; $slot = $#LITERALS; }
    _string($t, $lang, $w, $c, $raw);
    return unless $COLLECT;
    my $to = length $$w;
    my $close = $raw ? '"""' : '"';
    $to -= length $close if substr($$w, $to - length $close) eq $close && $to - length $close >= $from;
    $LITERALS[$slot][1] = substr($$w, $from, $to - $from);
}

# A string body after its opening quote(s), through its closing quote(s).
sub _string {
    my ($t, $lang, $w, $c, $raw) = @_;
    while (pos($$t) < length $$t) {
        if ($raw && $$t =~ /\G("{3,})/gc) {
            # `""""` closes a raw string whose last character is a quote: the last three close it.
            my $q = length $1;
            _body($w, $c, '"' x ($q - 3)) if $q > 3;
            _both($w, $c, '"""');
            return;
        }
        if (!$raw && $$t =~ /\G"/gc) { _both($w, $c, '"'); return; }
        if (!$raw && $$t =~ /\G(\\.)/gcs) { _body($w, $c, $1); next; }
        if ($lang eq 'kotlin' && $$t =~ /\G\$\{/gc) {
            _both($w, $c, '${');
            _code($t, $lang, $w, $c, 1);
            next;
        }
        if ($lang eq 'kotlin' && $$t =~ /\G(\$[A-Za-z_][A-Za-z0-9_]*)/gc) { _both($w, $c, $1); next; }
        if ($raw && $$t =~ /\G([^"\$]+)/gc) { _body($w, $c, $1); next; }
        if (!$raw && $$t =~ /\G([^"\\\$\n]+)/gc) { _body($w, $c, $1); next; }
        if (!$raw && $lang ne 'rust' && $$t =~ /\G\n/gc) { _both($w, $c, "\n"); return; }
        $$t =~ /\G(.)/gcs;
        _body($w, $c, $1);
    }
}

1;
