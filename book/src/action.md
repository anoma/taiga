# The Action circuit

The Action circuit is a mechanism that ensures that the proposed state transitions follow the Taiga rules. 
Unlike validity predicates, the Action circuit checks don't depend on the applications involved and are the same for all transactions.

As an application state is contained in notes, and a state transition is represented as spending the old notes and creating new ones,
the Action circuit checks the correctness of the old state by checking properties of the old notes and the correctness of the new state by checking the properties of the new notes.

### Check the old state (spent notes)

For spent notes, the Action circuit checks that:
* the note existed before (can you spend a note that doesn't exist?),
* the note haven't been spent yet,
* the spender has a right to spend it (do you own the note?),
* and that the application the note belongs to approves the action (sure there is some application approves the check, but is it the one the note belongs to?).

### Check the new state (created notes)

For the notes being created, the Action circuit checks that:
* the correct application approves it (same check as for spent notes)
* and the note commitment is derived correctly (the thing that makes everyone to know that the note exists must indeed represent the note)

To learn in details about the checks the Action circuit performs, check the [technical specification of Taiga](./spec.md).
