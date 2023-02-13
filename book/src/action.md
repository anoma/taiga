# The Action circuit

Every time a user wants to create or spend a note, 
the Action circuit check is required to make sure that the user doesn't violate Taiga rules. 
The conditions checked in the Action circuit are the same for all transactions, 
unlike validity predicate checks that depend on the applications involved in the transaction.

### Spent note checks

For spent notes, the Action circuit checks that:
* the note existed before (can you spend a note that doesn't exist?),
* the note haven't been spent yet,
* the user has a right to spend it (do you own the note?),
* and that the application the note belongs to approves the action (sure there is some application approves the check, but is it the one the note belongs to?).

### Created note checks

For the notes being created, the Action circuit checks that:
* the correct application approves it (same check as for spent notes)
* and the note commitment is derived correctly (the thing that makes everyone to know that the note exists)

To learn in details about the checks the Action circuit performs, check the [technical specification of Taiga](./spec.md).
