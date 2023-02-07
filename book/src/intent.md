# Intent Application

**Intent application** allows users to express their interests with high level of uncertainty about the final state transition. When a user doesn't have a fully specified interest but can be satisfied with multiple versions of a state transition, intents help.

Like all other applications, intent application has an application VP that defines the application logic. 
**Intent appVP** hierarchically enforces the check of **intent userVP**s that express the interests of the users involved, 
and **intent application notes** are used to keep the transaction unbalanced (to make sure it doesn't get published), until the interests of all users are satisfied.

The design of the intent application is easiest to understand by seeing how it helps to empower the execution model.

### Intent notes mechanism

Users express their preferences in their intent userVPs. For each intent userVP there is a corresponding note type derived from that userVP.
Notes of that type are responsible to make sure that the intent userVP used to derive their value base is satisfied.

Strictly speaking, the notes don't make the intent userVP to be satisfied, 
but rather make sure that the transaction doesn't get published until the intent userVP is satisfied.

When a user specifies their intent, they create an intent note with the value base derived from their VP and value 1.
This note gets spent (balancing the transaction) only when the underlying intent is satisfied. 
Only a fully balanced transaction can be published on the blockchain, 
and balancing the intent notes requires satisfying the intent userVPs.

### ----- To sort -----

Intent app notes are **dummy** notes - meaning that unlike "normal" notes, the merkle path isn't checked for them (but they can have arbitrary value and stored in the CMtree, just like "normal").

##### Step 3: Solve
Solvers receive intents from the intent gossip network and match them together in order to create transactions.

That implies that users need to give some information to the solvers that is sufficient to create partial transactions and transactions (to create proofs). In order to match two intents, the solver needs to know:
- intent userVPs of both matching parties

We are considering the model where a solver makes one step at a time and sends the step result back to the gossip network, where the partial solution meets the next solver in the chain.
In practice, the solver can continue solving instead of sending the result back to the gossip network if they can make the next step.

##### Partial vs final match

After the solver matches the notes, two cases are possible:
1. At least one of the total per-token balances computed by summing up the per-token balances of partial transactions doesn't equal the balancing value. In this case, the solver sends the data to the gossip network.
2. All total per-token balances are equal to the balancing values. A valid transaction can be created and published.
