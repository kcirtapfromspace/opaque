;; Browser review aid only. Opaque's server independently enforces authority.
;; Web Crypto writes the computed SHA-256 into bytes 0..31 and the service's
;; expected manifest digest into bytes 32..63. No credentials enter this module.
(module
  (memory (export "memory") 1 1)
  (func (export "review")
    (param $window i32) (param $uses i32)
    (param $created f64) (param $expires f64) (param $now f64)
    (result i32)
    (local $index i32) (local $difference i32)
    (loop $digest
      (local.set $difference
        (i32.or (local.get $difference)
          (i32.xor (i32.load8_u (local.get $index))
            (i32.load8_u (i32.add (local.get $index) (i32.const 32))))))
      (local.set $index (i32.add (local.get $index) (i32.const 1)))
      (br_if $digest (i32.lt_u (local.get $index) (i32.const 32))))
    (if (local.get $difference) (then (return (i32.const 1))))
    (if (i32.or (i32.ne (local.get $window) (i32.const 60))
                (i32.ne (local.get $uses) (i32.const 1)))
      (then (return (i32.const 2))))
    ;; Positive comparisons reject NaN as well as invalid or expired bounds.
    (if (i32.eqz (i32.and
          (f64.gt (local.get $expires) (local.get $created))
          (i32.and
            (f64.le (f64.sub (local.get $expires) (local.get $created)) (f64.const 300))
            (i32.and (f64.ge (local.get $now) (local.get $created))
                     (f64.lt (local.get $now) (local.get $expires))))))
      (then (return (i32.const 3))))
    (i32.const 0)))
