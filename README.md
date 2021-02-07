# UACBypassProcHollowSelfDeleteCpp

## PoC chaining some techniques together

### Summary
```
Get parent proc -> check if started by fod -> Reg set -> start fodhelper -> Reg Del -> Self Delete
                    |
                    |
                    |
                    V
               fodhelper.exe -> perform proc hollow and self delete
                                        |
                                        |
                                        |
                                        V
                             Elevated reverse shell

```
Self delete to cleanup, get elevated reverse shell.

# Credits
Below posts and repos helped alot.
* Self Delete -> @jonasLyk and  @LloydLabs https://github.com/LloydLabs/delete-self-poc
* Proc Enum -> @zwclose7 http://www.rohitab.com/discuss/topic/40504-using-ntquerysysteminformation-to-get-process-list/
