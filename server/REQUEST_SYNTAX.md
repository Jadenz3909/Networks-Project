## Connect to server
```python
tuple[username: str, password: str]
```
> Need to discuss how password encryption will work, will we use hashing?

## Upload file
```python
tuple[Literal["upload"], file_name: str, file_size_bytes: int, directory: str]
```
> Server responds with code **100** if ready or **404** if directory does not exist
> If /directory/file_name already exists, server will return **300**; If client responds true, proceed as normal, else halt
> Next **file_size_bytes** bytes received will be put into /directory/file_name
> Upon completion, the client should send the hash of the file
> If server file hash matches client hash, server will return **201**

## Download file
```python
tuple[Literal["download"], file_path: str]
```

## Delete file
```python
tuple[Literal["delete"], file_path: str]
```

## View directory contents
```python
tuple[Literal["dir"], directory: str]
```

## Create directory
```python
tuple[Literal["subfolder"], subfolder_name: str, directory: str]
```