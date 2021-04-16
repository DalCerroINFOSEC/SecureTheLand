Place Holder

Replacing the word 'Users' within a file path field.
| eval FilepathL=lower(Filepath)
| rex field=FilepathL mode=sed "s/\\\users\\\.*[^\\\]/<Username>/g"
