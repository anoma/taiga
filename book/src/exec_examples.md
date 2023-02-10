## Exectuion model examples

Let's see how different use cases can be handled with the Taiga execution model.

**Note**: For simplicity in the examples below we assume that the balancing value `v` is equal to zero.

### 1. Two-party exchange with an intent userVP

Let's consider the situation where one of the parties uses the intent application, and the other party doesn't.
Here Alice has two notes [1]A and [2]B and wants to get a blue dolphin NFT in exchange for one of them and get the other one back. 
Alice uses intent application to express her preferences. Bob has a blue dolphin NFT and wants [1] of token A in exchange for it. 
As Bob knows what he wants, no intent userVP needed.

![img_1.png](img/exec_complex_intent_plus_no_intent.png)

**Step 1-2**: Alice creates her intent userVP, both Alice and Bob create their initial partial transactions. 
Alice spends both of her notes she could give away, expecting to receive one of them back (the other one will go to the counterparty).

**Step 3**: A solver sees Alice's and Bob's partial transactions and matches them together. 
Alice receives the blue dolphin NFT and one of her notes ([2]B) back,
her intent userVP is satisfied and Alice's intent note is spent. Bob has already sent himself the note he wanted, so the solver doesn't create notes for Bob.
All total (accumulated over ptxs) per-token balances are equal to 0, and the final transaction can be created.

**Step 4**: The final transaction is created using the spent and output notes from the partial transactions.

#### Ptxs detailed description

||spent notes|created notes|Apps|VP proofs|total balance (accumulated)|
|-|-|-|-|-|-|
|ptx #1 (Alice)|[1]A, [2]B|[Alice intent note]|intent app, A token, B token|Alice intentVP, intent App VP, Alice A userVP, A appVP, Alice B userVP, B appVP (6)|-[1]A-[2]B + [Alice intent note]|
|ptx #2 (Bob)|[blue dolphin NFT]|[1]A|blue dolphin NFT app, A token|Bob A userVP, A appVP, Bob NFT userVP, NFT appVP (4)|-2[B] - [blue dolphin NFT] + [Alice intent note]
|ptx #3 (Solver)|[Alice intent note]|[blue dolphin NFT], [2]B|intent app, blue dolphin NFT app, B token|Alice NFT userVP, NFT appVP, Alice intent userVP, intent AppVP, Alice B user VP, B appVP (6)|0|

### 2. Three-party barter

Three parties, Alice, Bob, and Charlie, are looking for some assets in exchange for something else.
Their intents can be matched into a three-party bartering cycle. Let's see step by step how this happens.

**Note**: parties don't ask for a three-party bartering explicitly.

![img.png](img/exec_3_party.png)

**Step 1-2**: The users define their intents and create intent userVPs.
It doesn't have to happen at the same time for all users, but for simplicity we describe it as one step.
The intent userVPs of all three users have the same structure: users are willing to spend their asset (Alice - a star, Bob - a dolphin, Charlie - a tree) in exchange for some other asset.
Once the user receives the desired asset, the intent note is spent.
In addition to that, all three users also create their initial partial transactions spending the asset they are ready to give away (Alice ptx, Bob ptx, and Charlie ptx).

**Step 3**: A solver sees Alice's ptx and Bob's ptx, matches them together, and creates a new partial transaction.
Alice's intent userVP is satisfied, and her intent note is spent.

Total per-token balances:

|token|spent|output|spent - output|
|-|-|-|-|
|star NFT|1|0|1|
|blue dolphin NFT|1|1||
|blue intent|[1] - [1]|-|0|
|yellow intent|[1] |-|[1]|

**Step 4**: A solver sees all previous partial transactions, and the initial transaction created by Charlie.
The solver matches them together and creates new partial transactions, sending the tree to Bob and the star to Charlie.
VPs of Bob and Charlie are now satisfied, the corresponding intent app notes are spent.
The  per-token balance of partial transactions is equal to zero, which means it is possible to create a transaction.
Total per-token balances:

|token|spent|output|spent - output|
|-|-|-|-|
|star NFT|1|1|0|
|blue dolphin NFT|1|1|0|
|blue intent|[1] - [1] = [0]|-|0|
|yellow intent|[1] - [1]|-|0|
|tree NFT|1|1|0|
|green intent|[1] - [1]|-|0|

**Step 5**:
The final transaction containing the spent and output notes from partial transactions is created with all proofs attached.

### 2. Three-party barter without intents
![img.png](img/exec_3_party_no_intents.png)



### 3. One way to represent arbitrary states

For an arbitrary application, notes store the state of the application. When the application needs to change its state,
it (i.e. any party that has the authority) can spend the old state and produce a new state.
If the state change is possible within one partial transaction, such a note has a value 0 and doesn't affect the total balance.
![img.png](img/exec_arbitrary_state_update.png)

If the state change happens across partial transactions (meaning that the state gets consumed in one partial transaction, and a new state is output in another),
the process is a bit different.

#### State transition across partial transactions

![img_1.png](img/exec_update.png)

For simplicity, let's assume that the old state note has a 0 value.
A zero-value note doesn't affect the total balance which is necessary for across-ptx communication.
And so the first step is to turn a zero-value note into a non-zero value note (step 1 on the diagram).

In the next partial transaction (step 2) we spend a [1] value note to balance the created [1] state note,
but if the state can be changed to final in the next partial transaction (step 2.1), a new state zero-value note is produced,
total balance becomes zero, and the transaction can be finalized. If the state isn't final (step 2.2),
another [1] value note with the new (but not final) state is produced, the total balance is non-zero and the transaction cannot be finalized.
In that case, the step 2 is repeated until the final state is computed.

**Note**: different states imply different token types, and the old state note cannot balance a new state note.
