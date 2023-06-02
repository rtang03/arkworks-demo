### test execution result

```text
❯ cargo test good_root_test -- --nocapture
   Compiling arkworks-demo v0.1.0 (/Users/tangross/dev/2023/arkworks/arkworks-demo)
    Finished test [unoptimized + debuginfo] target(s) in 3.84s
     Running unittests src/lib.rs (target/debug/deps/arkworks_demo-ef0627771cccb03c)

running 1 test
=== leaf 0 / [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] ===
contraints from digest: 21
constraints from leaf and twoToOne parameters: 0
constraints from leaf: 632
constraints from path: 44
number of constraints: 13886
=== leaf 1 / [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] ===
contraints from digest: 21
constraints from leaf and twoToOne parameters: 0
constraints from leaf: 632
constraints from path: 44
number of constraints: 13886
=== leaf 2 / [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2] ===
contraints from digest: 21
constraints from leaf and twoToOne parameters: 0
constraints from leaf: 632
constraints from path: 44
number of constraints: 13886
=== leaf 3 / [3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3] ===
contraints from digest: 21
constraints from leaf and twoToOne parameters: 0
constraints from leaf: 632
constraints from path: 44
number of constraints: 13886
=== update query at pos 3 / [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7] ===
contraints before update: 0
constraints from leaf and twoToOne parameters: 0
constraints from new_leaf: 632
constraints from old_leaf: 632
constraints from old_root: 3
constraints from old_path: 8
constraints from new_root: 3
test merkle_tree::constraints::byte_mt_tests::good_root_test ... ok
```
