# The Intent Application

The **intent application** allows users to express their interests with high level of uncertainty about the final state transition. 
When a user doesn't have a specific interest but can be satisfied with multiple versions of a state transition, intents help.

**Note**: Users can still use intents to express their interests even when they know what they want, but it is more expensive and often unnecessarily complicated.

Like all other applications, the intent application has an application VP that defines the application logic. 
Users of the intent application express their preferences in their userVPs.
Intent application VP hierarchically enforces the check of intent userVPs, 
and intent application notes are used to keep the transaction unbalanced (to make sure it doesn't get published), 
until the interests of all users are satisfied.

### Intent notes

Users express their preferences in their intent userVPs. For each intent userVP there is a corresponding note type derived from that userVP.
Notes of that type are responsible to make sure that the intent userVP used to derive their type is satisfied.

Strictly speaking, the notes don't make the intent userVP to be satisfied, 
but rather make sure that the transaction doesn't get published until the intent userVP is satisfied.

When a user specifies their intent userVP, they create an dummy intent note with the type derived from the userVP and value 1.
This note gets spent (balancing the transaction) only when the corresponding intent is satisfied. 
Only a fully balanced transaction can be published on the blockchain, 
and balancing the intent notes requires satisfying the intent userVPs.

#### How to use the intent application

1. Spending notes in the initial partial transaction, the user additionally outputs intent note of value [1].
   This note will only be spent if the user's intent userVP is satisfied.
2. Once all the parties involved in a state transition spent their intent app notes (meaning that the interests of all of them are satisfied), the transaction is balanced and can be finalized.
  
![img.png](images/exec_intent_notes.png) 

**Note**: The solvers need to know the content of the intent userVPs to know how to satisfy them.