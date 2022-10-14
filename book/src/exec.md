# Taiga execution model

## On a high level
Users use intents when they want to enact a multiparty state transition. High level description of the flow:
1. **Create**: User creates an intent publishing the information of what they have and what they want to get in exchange
2. **Gossip**: The intent goes to the intent gossip network and gossiped around the solver nodes.
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

Note: roles, other users that can create ptx)

In the initial partial transaction the user spends the assets they were willing to spend as a part of the intent and outputs an **intent token note**.

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

**Note**: intent token notes are not committed to in the global CMtree

**Note**: The content of the intentVP in revealed to the solver so that they can create a transaction that satisfies this VP

### Solve
We are considering the model when a solver makes one step at a time and sends the result to the next solver. In practice, the solver can send the result to themselves and continue solving if they have the intent to make the next step. It would be nice to merge the steps into one when possible, but for simplicity we ignore this detail here

#### Create partial transactions

When a solver has two intents that can be matched together, they match the intents by spending the old notes and creating new notes. 

##### Prove
Solvers are responsible for creation of all proofs (`Action`, `tokenVP`, `userVP`, etc) required for a state transition for their partial solutions.
- solvers **have the authority** to spend and create the intermediate notes they receive and produce the proofs required to perform the action
- solvers **know** the content of intent-specific VPs and receving VPs of the users (necessary to be able to satisfy them)
- solvers **don't know** the identities of the users

When solvers receive partial transactions, they must check all of the proofs attached to it.

##### Local `cm` trees

To store intermediate note commitments `cm`, a local commitment tree `CMtree` is created. After the transaction is finalized, the tree will be published on the blockchain along with the transaction.

#### Partial vs final match

If a solver has two intents that can be matched together, two cases are possible:
1. The match is partial, partial transaction and a new intent are created. In this case the solver appends the data they produced to the new intent and gossips the new intent to the next node
2. The match is final, the solver publishes the final transaction as described below

**Note**: in the current implementation we assume a simpler model where only one solver can match n-party bartering intents (**no partial solving**).

**Note**: solvers don't need to be identified as all actions are authorized by user/app VPs. However, if they want to receive fees, they need to have an address on the chain.

### Publishing partial transactions

Publishing partial transactions on the blockchain shouldn't be possible. 

If intermediate notes have a completely different type from normal notes, this isn't a problem as the correct transaction should only contain notes of the right type. 

If intermediate notes have the same type as normal notes and only differ in the purpose of existence, this could be a problem (although in the simplified setting without partial solving it wouldn't be)

### Finalize

After the intents are matched with satisfaction of all involved parties, the transaction is published on the blockchain. The intermediate notes themself are not published, but the local CMTree is, as well as all of the proofs created (including the proofs for the intermediate notes).

### Example with a 3-party bartering cycle

On the example below Alice, Bob, and Carol want to exchange some assets (not necessarily with each other). 

1. All three of the users create intermediate notes with intent-specific VPs.

2. Alice and Bob create their intents and send them to the intent gossip network. 
   
2.1 Carol creates her intent and sends it to the intent gossip network.

3. The first solver receives the intents of Alice and Bob (but not necessarily Carol's), matches them, and produces a partial tx. This partial transaction satisfies the needs of Alice but not Bob's and cannot be finalized. Solver produces a new intent (seeking for the resources to satisfy Bob's VP).

4. The second solver receives the intent produced by the first solver and Carol's intent and matches them. The resulting transaction satisfies the needs of Alice, Bob, and Carol and can be finalized.

5. The final transaction doesn't contain intermediate notes, but contains commitments to them. In the end, Alice sends her note to Carol, Carol sends her note to Bob, and Bob sends her note Alice.

![img.png](img/exec_img.png)
