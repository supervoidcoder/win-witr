# win-witr [wip]

## why is this running?
## now for windows 😎



an in progress "port" of witr built from the ground up in C++

The original witr project is made by Pranshu Parmar (@pranshuparmar) and is available at: https://github.com/pranshuparmar/witr

While this is inspired by that project, this does not contain any actual code from the original project, since I've decided to rebuild this in C++ rather than Go.

when this is done I will submit this to winget!!

**Why C++?**

- I don't know crap about Go
- It can natively talk to the kernel rather than weird wrapper crap
- idk it's more fun to write

**Why did I even make this?**

I heard that the original dev wasn't planning to make a Windows version for it.
He was probably right.
Oh it is such a pain to work with the windows kernel.
Windows is the most popular and the most user friendly and organized looking OS but the SECOND you peek inside it is such a garbling mess of WEIRD stuff. It's so weird.
Some quirks I've noticed:
- In Linux, when a parent process dies (such as, a process spawns a child process and then ends itself), the kernel politely adopts the child process to avoid it from floating as an orphan. Windows, on the other hand, is a merciless masochistic psychopath and will leave processes connected to a ghost PID. Sometimes, Windows frees the parent PID up and something immediately snatches it, so a parent PID can be deceiving.
- The kernel stuff is complicated as heck for no reason. Like everything is so separated and needs very weirdly specific workarounds that it's almost eerie.


I could've definitely done this in one sitting if I only had like 5 more hours but I decided i will stop right here and this is pretty good for the initial commit. 300-400 lines of C++ ain't that bad for 3 hours, and I want to spend the remaining 2 hours of this day to spend New Years with my family.


## AI assistance disclaimer

A code review assistant known as CodeRabbit (@coderabbitai) will be in this repo to assist me with reviewing code.
Please do not submit PRs with AI-generated content.
Trust me, you can use AI for quick little JS or Python crap, but you do NOT want AI making a whole C++ app. It'd allocate 16/8GB of ram without hesitation. It'll explode your computer. Bamboozle it. Flabbergast it. Flabberbamboozle it. 

Uh,

-supervoidcoder