### Cryptopals in Rust

This is my attempt to do all the sets and challenges in the famous
[Cryptopals](https://cryptopals.com/) teaching project. I've decided to
structure each set as it's own rust library and have each challenge as a test
in that library. The tests should be a rust translation of the challenge
verifications on the site.

Eventually the idea is that this project can be used as a structure for future
folk who'd like to go thought the [Cryptopals](https://cryptopals.com/) in
rust. All my function implementations can be replaced by a `todo!()` macro,
making the project compile, and then it'd be up to the student to actually
implement these functions to pass the tests.
