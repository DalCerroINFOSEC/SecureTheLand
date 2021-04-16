Place Holder

#### Replacing the word 'Users' within a file path field.
```ruby
| eval FilepathL=lower(Filepath)
| rex field=FilepathL mode=sed "s/\\\users\\\.*[^\\\]/<Username>/g"
```
---
