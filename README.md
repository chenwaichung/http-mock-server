# HTTP Mock Server

## 功能
HTTP Mock Server 是一个图形用户界面工具，用于模拟 HTTP API。它允许用户定义 API 路径、请求方法、请求验证规则（如 JSON Schema、Headers 和 Form Data）以及响应内容和头部。用户可以通过简单的界面进行配置，并启动一个本地服务器来处理请求。

## 安装依赖
在开始之前，请确保你已经安装了 Python 3.7 或更高版本。然后，你可以使用以下命令安装所需的依赖：

### 使用 `requirements.txt`
```bash
pip install -r requirements.txt
```

### 或者使用 `pyproject.toml`
```bash
pip install .
```

## 构建
要构建项目，你需要使用 PyInstaller。确保你已经安装了 PyInstaller：

```bash
pip install pyinstaller
```

然后，使用以下命令构建项目：

```bash
pyinstaller http-server.spec
```

构建完成后，可执行文件将位于 `dist` 目录下。

## 打包
要打包应用为可执行文件，使用以下命令：

```bash
pyinstaller --onefile http-test-server.py
```

这将创建一个单独的可执行文件，位于 `dist` 目录中。

## 使用
1. 启动应用程序：
   ```bash
   python http-test-server.py
   ```

2. 在 GUI 中，您可以添加 API 配置，设置请求验证规则和响应内容。

3. 启动服务器并使用工具（如 Postman 或 curl）测试 API。

## 示例
以下是一个示例 JSON Schema，用于验证用户登录请求：

```json
{
  "type": "object",
  "properties": {
    "userName": {
      "type": "string",
      "minLength": 3
    },
    "userPass": {
      "type": "string",
      "minLength": 3
    }
  },
  "required": ["userName", "userPass"]
}
```

## 许可证
此项目使用 MIT 许可证。有关详细信息，请参阅 LICENSE 文件。
