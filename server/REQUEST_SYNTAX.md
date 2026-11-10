## Connect to server
```python
tuple[username: str, password: str]
```
> Need to discuss how password encryption will work, will we use hashing?

## Upload file
```python
tuple[Literal["upload"], file_name: str, file_size_bytes: int, directory: str]
```
> Next **file_size_bytes** bytes received will be put into /directory/file_name

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