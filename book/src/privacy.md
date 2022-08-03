# Full privacy

* What leaks info with custom VPs
* How we fix it: we randomize the verifier keys.
* In consequence we need to bind randomizedVK to VK. We use another commitment.
* Blinding proof is split in two parts:
    * vk and rand leads to randomizedVK,
    * vk opens vkCommitment.