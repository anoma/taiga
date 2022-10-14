# Taiga execution model

## On a high level
Users use intents when they want to enact a multiparty state transition. High level description of the flow:
1. **Create**: A user creates an intent publishing the information of what they have and what they want to get
2. **Gossip**: The intent goes to the intent gossip network and is gossiped around the solver nodes.
3. **Solve**: Solvers find matching intents and update the intent with partial transactions until the intent is fully satisfied
4. **Finalize**: When the intent is satisfied, a transaction is created and published on the blockchain

![img.png](img/exec_high.png)

### Create an intent

Intents specify ephemeral interests of the users. The step of creating an intent can be split into two:
1. **Specify an intent**. IntentVP encodes the needs of the user and enforces their satisfaction.
2. **Create a partial transaction**. 

**Note**: For simplicity we assume that an intent includes a user sending some of their notes and receving some other notes.

#### Partial transaction

Two of the main requirements for a transaction to be valid are 
1. VPs of all involved parties must be satisfied
2. The transaction must be balanced (the value spent = the value output for all involved token types)

We call a **partial transaction** a state transition where the first requirement is satisfied (all VPs evaluate to True), but the second one isn't (the state transition is unbalanced). Such a state transition isn't a valid transaction and cannot be published on the blockchain, 
but can be combined with other partial transactions in order to build a valid [balanced] transaction. 

Partial transactions can be created by solvers who match intents and create transactions, and by users who spend their notes as a part of creating an intent.

Note: as an object, partial transactions are immutable
Note: roles, other users that can create ptx)

In the initial partial transaction the user spends the assets they were willing to spend as a part of the intent and outputs an **intent token note**.

To Do: add a diagram

#### Intent tokens

To make sure that the user's intent being satisfied, we use **intent tokens**. Intent token notes is a special type of notes that cannot be spent, but only created. In addition, intent notes can have negative value.

How to use intent tokens:
1. Spending their notes in the initial partial transaction, the user additionally spends an intent token note of value [1].
2. The other note of value [-1] balancing this token will only be created if the user's intent is satisfied.
3. Once all of the parties involved in a state transition create their [-1] intent token notes (meaning that the intents of all of them are satisfied), the transaction is balanced and can be finalized.

If we look at the notes as messages passing from one user (application to another), the first [1] intent note can be seen as message being sent, when the [-1] note will signal that the message has been received. See more about message passing [here](./message_passing.md).

**Note**: instead of using notes of negative value the user can instead spend a [1] intent token note (that haven't been created before) in their initial partial transaction. Once the user's intent is satisfied, a [1] intent note will be output balancing the initial spend.


Once intentVP is specified and the initial partial transaction is created, the user sends the intent to the intent gossip network and solvers match intents in order to create full transactions and publish them on the blockchain. That implies that users need to give some information to the solvers that is sufficient to create partial transactions and transactions (proofs)

To Do: what is the minimal amount of information needs to be revealed to the solver in order to match a transaction?
To Do: add a diagram

**Note**: intent token notes are not committed to in the global CMtree

**Note**: The content of the intentVP in revealed to the solver so that they can create a transaction that satisfies this VP

### Solve
We are considering the model when a solver makes one step at a time and sends the result to the next solver. In practice, the solver can send the result to themselves and continue solving if they have the intent to make the next step. It would be nice to merge the steps into one when possible, but for simplicity we ignore this detail here

#### Create partial transactions

When a solver has two intents that can be [partially] matched together, they [partially] match the intents by creating new partial transactions. The intentVPs or other partial transactions are not modified.

##### Prove
Solvers are responsible for creation of all proofs (`Action`, `tokenVP`, etc) required for a state transition for their partial solutions.
- solvers **have the authority** to spend and create the notes they receive and produce the proofs required to perform the action
- solvers **know** the content of intentVPs of the users (necessary to be able to satisfy them)
- solvers **don't know** the identities of the users

When solvers receive partial transactions, they must check all of the proofs attached to them.

##### Local `cm` trees

To store intermediate note commitments `cm`, a local commitment tree `CMtree` is created. After the transaction is finalized, the tree will be published on the blockchain along with the transaction.

#### Partial vs final match

After the solver matches the intents, two cases are possible:
1. The total balance computed by summing up the balances of partial transactions is a non-zero value. The solver gossips the data to the next gossip node
2. The total balance is equal to 0. A valid transaction can be created and published

**Note**: in the current implementation we assume a simpler model where only one solver can match n-party bartering intents (**no partial solving**).

**Note**: solvers don't need to be identified as all actions are authorized by user/app VPs. However, if they want to receive fees, they need to have an address on the chain.

### Finalize

After the intents are matched with satisfaction of all involved parties, the transaction is published on the blockchain. The local CMTree and all of the proofs created are published on the blockchain.

### Example with a 3-party bartering cycle

To Do: describe the new examples, with diagrams

To Do: add the userVP update