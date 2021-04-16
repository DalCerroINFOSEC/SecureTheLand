Place Holder

#### Replacing the word 'Users' within a file path field.
```ruby
| eval FilepathL=lower(Filepath)
| rex field=FilepathL mode=sed "s/\\\users\\\.*[^\\\]/<Username>/g"
```
---

#### Pulling out text(exe name in this case) after the last '\' and excluding anything after and including a whitespace.
Before:  
C:\Windows\System32\conhost.exe  
After:  
conhost.exe  
```ruby
| eval New_Process_NameL=lower(New_Process_Name)
| rex field=New_Process_NameL mode=sed "s/.*\\\(.*[^\s])/\1/g" 
| stats values(New_Process_NameL)
```
