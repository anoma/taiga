### High level idea
Users use intents when they want to exchange their assets for some other asset. High level description of the flow:
1. **Create**: User creates an intent publishing the information of what they have and what they want to get in exchange
2. **Gossip**: The intent goes to the intent gossip network and gossiped around the solver nodes.
3. **Solve**: Solvers find matching intents and update the intent until it is fully satisfied
4. **Finalize**: When the intent is satisfied, a transaction is created and published on the blockchain

### Create an intent
User intents can be seen as partial transactions. Users send them to the intent gossip network and solvers match them in order to create full transactions and publish them on the blockchain. That implies that users need to give some information to the solvers that is sufficient to create the final transaction (proofs). To make sure that users reveal the minimal amount of private infortmation that is still enough to create the transaction, users create **intermediate notes** from the notes they are willing to spend.

#### Intermediate notes
An intermediate note is a note with a simplified sending VP. This VP is specific to the intent and contains only the rules that are necessary to satisfy for the transaction to happen. All of the note fields stay the same except:
- sending VP -> intept-specific VP
- owner address -> intent-specific owner address (sending VP is used to calculate the owner address, so changing the VP implies the change of the owner address)

The creation of the intermediate note can be seen as sending a note to a new address with intent-specific VP.

Note: as the *nullifier key* **nk** is also used to calculate the address, so the VP doesn't solely define the address

Note: The content of intent-specific VPs in known to the solver because the solver will create the final transaction and some of the proofs

Note: intermediate notes will not be published

#### Gossip
Not much to say here in the context of Taiga execution but might be helpful to preserve the structure of the page

#### Solve
We are considering the model when a solver makes one step at a time and sends the result to the next solver. In practice, the solver can send it to themselves and continue solving if they have the intent to make the next step

Note: it would be nice to merge the steps into one when possible


#### Finalize
