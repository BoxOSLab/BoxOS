## Summary

<!-- What does this change and why? One paragraph plus bullets.
     Reference any C-PRoot counterpart file/function for parity changes. -->

## Test plan

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets --locked -- -D warnings`
- [ ] `cargo test --locked`
- [ ] `cargo deny check`
- [ ] Upstream C suite green (`make -C ../proot/tests test PROOT=…`) — required for behavior changes
- [ ] Docs updated (docs/ chapter, man page, or rustdoc) — required for user-visible changes

## Notes

<!-- unsafe introduced? parity deviation? follow-up work? -->
