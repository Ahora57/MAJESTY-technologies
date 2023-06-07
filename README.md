# MAJESTY-technologies
Little driver for protecthion.  
The driver is still under development, so you can submit your ideas!  
I write it's for manual map driver,because i havn't sertivicate for driver.  

Version 1.3

Support windows 10-11!!  
You can remove/fix some detect with signature for work on windows 7,7sp1,8,8.1!  

I try do this driver use max DKOM   
 
Anti-UM debug:  
1)PEPROCESS -> DebugPort  
2)PEPROCESS -> NoDebugInherit  
3)PETHREAD -> HideFromDebugger(set manual like:EAC)  
4)PEPROCESS -> InheritedFromUniqueProcessId and compare with explorer.exe  
5)Check hardware breakpoint  
6) Set ProcessDebugPortMutex and ValidAccessMask to 0  

Anti-analysis:  
1)Check InstrumentationCallback( PEPROCESS -> Pcb -> InstrumentationCallback)  
2)Do process proteced  
  
Anti-KM debug:  
1)Check offset(like:KdEnteredDebugger)  
2)Check KdFuncthion on return STATUS_DEBUGGER_INACTIVE  
  
Anti-Hypervisor:  
1)Time attack  
2)check anomalies  
  
To-do list:  
1)write communicathion(UM <-> KM)  
2)Use hash for get address NtApi  
3)Check some hook?  

Check instrumentation callbacks(under VMware) ->  
![alt text](https://github.com/LazyAhora/MAJESTY-technologies/blob/main/Detect%20instrumentation%20callbacks.png)  
Set protect process ->  
![alt text](https://github.com/LazyAhora/MAJESTY-technologies/blob/main/Protect%20Process.png)  
Running under HyperHide  ->  
![alt text](https://github.com/LazyAhora/MAJESTY-technologies/blob/main/Under%20HyperHide.png)  
Set ValidAccessMask to 0  ->  
![alt text](https://github.com/LazyAhora/MAJESTY-technologies/blob/main/Dead%20ValidAccessMask.png)  
Set DbgkpProcessDebugPortMutex to 0 ->  
![alt text](https://github.com/LazyAhora/MAJESTY-technologies/blob/main/Dead%20DbgkpProcessDebugPortMutex.png)  
Try open R/W handle to protected process ->  
![alt text](https://github.com/LazyAhora/MAJESTY-technologies/blob/main/Open%20handle%20to%20protected%20process.png)  
