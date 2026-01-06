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
Some quirks I've noticed since I started working on this:
- In Linux, when a parent process dies (such as, a process spawns a child process and then ends itself), the kernel politely adopts the child process to avoid it from floating as an orphan. Windows, on the other hand, is a merciless sadistic psychopath and will leave processes connected to a ghost PID. Sometimes, Windows frees the parent PID up and something immediately snatches it, so a parent PID can be deceiving.
- The kernel stuff is complicated as heck for no reason. Like everything is so separated and needs very weirdly specific workarounds that it's almost eerie.
- To get the uptime of a process, the Windows kernel politely tells you the raw FILETIME of a process. But that isn't exactly... readable. In fact, it represents the amount of 100-nanosecond intervals since January 1, 1601, in the UTC timezone. Microsoft, WHAT? Literally every other piece of software uses Unix time, which is the number of **seconds** since January 1, 1970, in the UTC timezone. In Linux, you can just read the /proc/PID/stat file and get the uptime in seconds.
- Everything in Windows that's stupid like this is simply because of legacy reasons. While newer versions of Windows look like a shiny new (although heavily bloated) OS with a nice user-friendly UI and a whole crap ton of WebView2's and RAM hogs, the kernel is still the same mess of code that was written like 30 years ago. To cut them some slack, the Windows NT kernel was worked on by a bunch of people simultaneously which can lead to conflicting ideas, decisions, and other stuff. Linux, on the other hand, was written by one person (Linus Torvalds) and a small team of volunteers, so it has a much more consistent design than whatever this monstrosity is. Anyways, the other reason is compatibility. Even if Microsoft _wants_ to change something, millions of facilities use custom-written applications that rely on old behavior, especially things like hospitals and other infrastructure. (I bet banks are still written in COBOL or FORTRAN tho lol)




## AI assistance disclaimer

A code review assistant known as CodeRabbit (@coderabbitai) will be in this repo to assist me with reviewing code.
Please do not submit PRs with AI-generated content.
Trust me, you can use AI for quick little JS or Python crap, but you do NOT want AI making a whole C++ app. It'd allocate 16/8GB of ram without hesitation. It'll explode your computer. Bamboozle it. Flabbergast it. Flabberbamboozle it. 

Uh,

-supervoidcoder