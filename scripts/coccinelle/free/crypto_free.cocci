///
/// Structures allocated by crypto_alloc_* must be freed using crypto_free_*.
/// This finds freeing them by kfree.
///
// Confidence: Moderate
// Copyright: (C) 2014 Konstantin Khlebnikov,  GPLv2.
// Comments: There are false positives in crypto/ where they are actually freed.
// Keywords: crypto, kfree
// Options: --no-includes --include-headers

virtual org
virtual report
virtual context

@r depends on context || org || report@
expression x;
@@

(
 x = crypto_alloc_base(...)
|
 x = crypto_alloc_cipher(...)
|
 x = crypto_alloc_ablkcipher(...)
|
 x = crypto_alloc_aead(...)
|
 x = crypto_alloc_instance(...)
|
 x = crypto_alloc_instance2(...)
|
 x = crypto_alloc_comp(...)
|
 x = crypto_alloc_pcomp(...)
|
 x = crypto_alloc_hash(...)
|
 x = crypto_alloc_ahash(...)
|
 x = crypto_alloc_shash(...)
|
 x = crypto_alloc_rng(...)
)

@pb@
expression r.x;
position p;
@@

* kfree@p(x)

@script:python depends on org@
p << pb.p;
@@

msg="WARNING: invalid free of crypto_alloc_* allocated data"
coccilib.org.print_todo(p[0], msg)

@script:python depends on report@
p << pb.p;
@@

msg="WARNING: invalid free of crypto_alloc_* allocated data"
coccilib.report.print_report(p[0], msg)
