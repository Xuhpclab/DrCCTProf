There are several types of possible deadlock.  
1. Circular Wait:  
   (1) Two goroutines:
   We may obtain a record similar to this from the client:
   ```
   goid 1: l1 l2 u2 u1
   goid 2: l2 l1 u1 u2
   ```
   The l means lock and u means unlock. The client is able to detect this kind of deadlock.  
   (2) Multiple goroutines:
   The more general situation is that there is a circular-wait condition  between several goroutines. For example:
   ```
   goid 1: l1 l2 u2 u1
   goid 2: l2 l3 u3 u2
   goid 3: l3 l4 l5 u5 u4 u3
   goid 4: l5 l1 u1 u5
   goid 5: l4 u4
   ```
   In this example, if the record looks like this at some point:
   ```
   goid 1: l1
   goid 2: l2
   goid 3: l3 l4
   goid 4: l5
   goid 5: l4 u4
   ```
   , then there is a circular-wait condition:  
   goid 1 -> goid 2 -> goid 3 -> goid 4 -> goid 1. To detect circular waiting, we can start from a lock record in a goroutine. If there is a previous lock before this lock, search the previous lock in other goroutines. And repeat the procedure on the searched result. If finally there is a lock of a mutex that is identical to the first lock's mutex, there is a circular-wait condition. But the time complexity is very large. If there are m goroutines and n mutex, the time complexity is O(n*m^(n+1)).

2. Consecutive locks:  
   (1) Correct code:  
   In Go programs, mutex can be used to establish a relative ordering.
   ```
   var l sync.Mutex
   var a string
   
   func f() {
	   a = "hello, world"
	   l.Unlock()
   }
   
   func main() {
	   l.Lock()
	   go f()
	   l.Lock()
	   fmt.Println(a)
   }
   ```
   We will obtain two consecutive *l.Lock()* in the main goroutine's record. But this code doesn't have any bug. The first *l.Lock()* happens before the creation of the goroution. And the *l.Unlock()* happens before the second *l.Lock()*.  

   (2) Consecutive locks:  
   Sometimes the record with consecutive locks just means that the code has a bug. 
   ```
   var l sync.Mutex
   var a string

   func f() {
       l.Lock()
 	   l.Lock()
	   a = "hello, world"
   }

   func main() {
	   go f()
	   fmt.Println(a)
   }
   ```
   In this code, there are two consecutive *l.Lock()* that causes the child goroutine to be blocked. If this bug happens in the main goroutine, the program will output 
   ```
   fatal error: all goroutines are asleep - deadlock!
   ```
   , print stack information, and exit. But if this bug happens in other goroutines and it doesn't block the main goroutine, the program will exit after the main goroutine ends and won't output any information. We need to trace other goroutines' execution to see if they are blocked after consecutive locks to detect such kind of bug.  
   
