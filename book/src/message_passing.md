# Message passing

### Token in a general sense
Abstracting away from the notion of a token as a way to represent money, a token is just a system application (in a broad sense) label. The use of different tokens implies different system applications (which can have the same functionality but still be considered different, like Sprite and 7up).

Tokens (or rather the applications they represent) can have a bigger scope (e.g. the usual currency tokens) or a smaller scope (e.g. tokens used to protect the interests of a specific user in partial transactions)

### Token design in Anoma/Taiga

Each token has a tokenVP that defines the way to use the notes of that token type. In a correct transaction, tokenVPs must be satisfied. Each note has a token type and a value. The token data in a note is derived from the tokenVP.

![](https://i.imgur.com/AgYtx5H.png)

### Message passing

The idea of message passing is to view each tokenVP as a message, and the note encoding the message will serve as a carrier of the message

![](https://i.imgur.com/q34eh2L.png)

When a note carrying the message is created, the message is considered to be sent. When a note is spent (or a note with the inverse value is created), the message is considered to be received. The users can communicate with each other by sending messages. In a valid transaction, every sent message is received.

![](https://i.imgur.com/Gf2bpXX.png)


When users are just sending each other some assets, the message can simply be something like "Here is some XXX token", but different and/or more/less abstract applications can have arbitrary messages (that don't necessarily represent the value the same way as money do) encoded in notes 