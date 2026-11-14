## Connect to server
```python
{
    "username": str, 
    "password": str,
}
```
> Client sends username and password
> If auth is successful server responds **200**
> If auth is unsuccessful server responds **401** and closes connection

## Upload file
```py
{
    "cmd": "upload", 
    "file_name": str, 
    "file_size_bytes": int, 
    "dir": "/path/to/dir",
}
```
> Server responds with code **404** if directory does not exist
> If /directory/file_name already exists, server will return **300**; If client responds true, proceed as normal, else halt
> Server responds **100** if ready
> Next **file_size_bytes** bytes received will be put into /dir/file_name
> Upon completion, the client should send the hash of the file
> If server file hash matches client hash, server will return **201**
> If server file hash does not match client hash, server will return **422**

## Download file
```py
{
    "cmd": "download",
    "file_path": "/path/to/file",
} 
```
> If file does not exist server will return **404**
> Server will respond with the number of bytes, wait for a **200** response from client, and send the data

## Delete file
```py
{
    "cmd": "delete", 
    "file_path": "/path/to/file",
}
```
> If file does not exist server will return **404**
> Server will respond with **200** if deletion succeeds

## View directory contents
```py
{
    "cmd": "dir",
    "dir": "/path/to/dir",
}
```
> If dir does not exist server will return **404**
> Server will respond with **200** and a list of directory contents if dir exists

## Create directory
```py
{
    "cmd": "subfolder",
    "action": Literal["create", "delete"],
    "subfolder_name": "subfoldername",
    "dir": "/path/to/dir",
}
```
> If action is create and /dir/subfolder_name already exists server will respond **404**
> If action is delete and /dir/subfolder_name does not exist server will respond **404**
> Else server responds **200**