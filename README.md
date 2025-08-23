# binja_traceflow

a trace replay plugin for binary ninja.

step forward and backwards through traces of a binary's execution, to get a feel for its control flow.
let's get into [+ORC's "zen cracking"](https://github.com/redthing1/orc_book) mindset and understand intuitively how a binary flows.

record-and-replay debuggers exist for certain systems, but their applicability is somewhat limited and support is still not so great. if we care more about control flow, we can get a lot of the value very cheaply using pre-recorded traces.

## why

+ static dataflow analysis is cool, but only shows you the cfg
+ symbolic execution is awesome, but very slow and can’t handle system interaction
+ concrete debugging is powerful, but non-deterministic and often not reversible
+ trace replay is blazing fast and lets you time travel through control flow, loops, indirect branches

each of these approaches has its ups and downs. the first three are pretty well-supported, and i had a need for trace replay, so i built this.

## acknowledgements

+ [tenet](https://github.com/gaasedelen/tenet) for ui inspiration
+ [seninja](https://github.com/borzacchiello/seninja) for ui inspiration
