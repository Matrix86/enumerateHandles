# Windows Handles enumeration
Implementation of http://forum.sysinternals.com/howto-enumerate-handles_topic18892.html to enumerate all open handles on a Windows system

The function *NtQueryObject* with *ObjectNameInformation* can hang on named pipe and other objects, so this function was made on a different thread with a timeout.
C++ Libary Functions
