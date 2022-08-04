# Action

Taiga includes several proofs that need to be binded with the spent and created notes.
We describe the different bindings for both notes.

## Binding for the spent note
When a note is spent, several proofs are computed and need to be binded to the spent note fields and the nullifier:
* The token VP verifier key needs to be binded to the spent note token type (address),
* The sender `SendVP` verifier key needs to be binded to the spent note owner address,
* The nullifier of the spent note is computed with the nullifier key, and it needs to be binded to the spent note owner address.

```
tokVK------------------------------------> tokenAddress == Note.token_type
              |---> true/false
              |
tokProof------

sendVk--------------------------------------nk---------------> sender.address == SpentNote.owner_address 
                  |---> true/false           |
                  |                          v
sendProof---------                 Nullifier of the SpentNote
```

TODO real diagram

## Binding for the created note
When a note is created, proofs are also binded with its fields and the note commitment:
* The token VP verifier key needs to be binded to the created note token type (address),
* The receiver `RecVP` verifier key needs to be binded to the created note owner address,
* The created note commitment needs to be binded to the owner address, the token type (address), etc.

```
tokVK------------------------------------> tokenAddress == NewNote.token_type
              |---> true/false                   |
              |                                  |
tokProof------                             Newnote.commitment
                                                 |
recVk-------------------------------------> recevier.address == NewNote.owner_address 
                  |---> true/false          
                  |
recProof---------  
```

TODO real diagram


In practice, this bindings are done with openings of the different address commitments. These commitments are open in a private way using (again) zero-knowledge proofs. The verifier keys of the token and user VPs still leak private information and we use a blinding technique to get full privacy in Taiga.
