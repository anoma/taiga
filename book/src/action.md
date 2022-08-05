# Action

The action is a mechanism that allows a user to spend or create [notes](notes.md) by proving the right to do so using ZK proofs.

## Spending a note

To spend a note, the users need to prove that they are allowed to do so, namely:
- To make sure that the correct `token_VP` is checked, prove the relationship between `token_VK` and the token field in the spent note.
  ![img_3.png](img/action_img_3.png)
- To make sure the correct `send_VP`(read more about `send_VP` [here](./users.md)) is checked, prove the relationship between `send_VK` and the owner field in the spent note.
- Compute the nullifier of the spent note (using the nullifier key `nk`) so that it cannot be double-spent. To make sure that the nullifier is computed correctly, prove the relationship between `nk` and the owner field in the spent note.

![img_1.png](img/action_img_1.png)

## Creating a note

To create a note, the user also needs to prove the right to do so. `token_VP` must allow the creation of the note, as well as recipient user's `recv_VP`:

- To make sure that the correct `token_VP` is checked, prove the relationship between `token_VK` and the token field in the note to be created.
  ![img_4.png](img/action_img_4.png)

- To make sure the correct `recv_VP` is checked (read more about `recv_VP` [here](./users.md)), prove the relationship between `recv_VK` and the owner field of the note to be created.
  ![img.png](img/action_img.png)
  
- To make sure that the [note](./notes.md) commitment `cm` is derived correctly, prove the relationship between `cm`, the note, and the receiver of the note

![img_2.png](img/action_img_2.png)

To see a more detailed description of the action circuit checks, see the [specification](./spec.md). See also the [action implementation](https://github.com/anoma/taiga/blob/main/src/action.rs) and the [action circuit implementation](https://github.com/anoma/taiga/blob/main/src/circuit/action_circuit.rs) for more details.

To ensure full privacy, we use [blinding](./blinding.md) to hide the verifier keys.

