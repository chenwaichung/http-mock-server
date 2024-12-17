import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from flask import Flask, request, Response
import threading
import json
import webbrowser
from werkzeug.serving import make_server
import sqlite3
import logging
import socket
import jsonschema
from tkinter import ttk, scrolledtext, messagebox, font
import json
from idlelib.colorizer import ColorDelegator
from idlelib.percolator import Percolator

class JSONEditor(tk.Frame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.create_widgets()

    def create_widgets(self):
        # 创建工具栏
        toolbar = ttk.Frame(self)
        toolbar.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(toolbar, text="格式化", command=self.format_json).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="压缩", command=self.compact_json).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="验证", command=self.validate_json).pack(side=tk.LEFT, padx=2)
        
        # 创建编辑器
        self.editor = scrolledtext.ScrolledText(self, wrap=tk.WORD)
        self.editor.pack(fill=tk.BOTH, expand=True)
        
        # 设置等宽字体
        font_family = "Consolas" if "Consolas" in font.families() else "Courier"
        self.editor.configure(font=(font_family, 10))
        
        # 添加语法高亮
        self.colorizer = ColorDelegator()
        Percolator(self.editor).insertfilter(self.colorizer)

    def get_text(self):
        return self.editor.get("1.0", tk.END).strip()

    def set_text(self, text):
        self.editor.delete("1.0", tk.END)
        self.editor.insert("1.0", text)

    def format_json(self):
        try:
            text = self.get_text()
            if text:
                parsed = json.loads(text)
                formatted = json.dumps(parsed, indent=2, ensure_ascii=False)
                self.set_text(formatted)
        except Exception as e:
            messagebox.showerror("错误", f"JSON格式化失败: {str(e)}")

    def compact_json(self):
        try:
            text = self.get_text()
            if text:
                parsed = json.loads(text)
                compact = json.dumps(parsed, separators=(',', ':'), ensure_ascii=False)
                self.set_text(compact)
        except Exception as e:
            messagebox.showerror("错误", f"JSON压缩失败: {str(e)}")

    def validate_json(self):
        try:
            text = self.get_text()
            if text:
                json.loads(text)
                messagebox.showinfo("成功", "JSON格式有效")
        except Exception as e:
            messagebox.showerror("错误", f"JSON格式无效: {str(e)}")

class RequestParamsFrame(ttk.LabelFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, text="请求验证", **kwargs)
        self.create_widgets()

    def create_widgets(self):
        # 创建Notebook用于不同类型的验证
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # JSON验证标签页
        self.json_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.json_frame, text='JSON验证')
        
        # JSON验证选项
        self.json_type = tk.StringVar(value="none")
        ttk.Radiobutton(self.json_frame, text="不验证", variable=self.json_type, 
                       value="none").pack(anchor=tk.W)
        ttk.Radiobutton(self.json_frame, text="JSON Schema", variable=self.json_type, 
                       value="json_schema").pack(anchor=tk.W)
        
        # JSON Schema编辑器
        self.schema_editor = JSONEditor(self.json_frame)
        self.schema_editor.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Button(self.json_frame, text="插入示例Schema", 
                  command=self.insert_example_schema).pack(pady=5)

        # Headers验证标签页
        self.headers_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.headers_frame, text='Headers验证')
        
        # Headers验证选项
        self.headers_type = tk.StringVar(value="none")
        ttk.Radiobutton(self.headers_frame, text="不验证", variable=self.headers_type, 
                       value="none").pack(anchor=tk.W)
        ttk.Radiobutton(self.headers_frame, text="必需Headers", variable=self.headers_type, 
                       value="required").pack(anchor=tk.W)
        
        # Headers列表
        headers_list_frame = ttk.Frame(self.headers_frame)
        headers_list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Headers表格
        columns = ('名称', '值模式')
        self.headers_tree = ttk.Treeview(headers_list_frame, columns=columns, show='headings')
        for col in columns:
            self.headers_tree.heading(col, text=col)
            self.headers_tree.column(col, width=100)
        self.headers_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Headers编辑区域
        headers_edit_frame = ttk.Frame(self.headers_frame)
        headers_edit_frame.pack(fill=tk.X, pady=5)
        
        self.header_name = tk.StringVar()
        self.header_pattern = tk.StringVar()
        
        ttk.Label(headers_edit_frame, text="Header名称:").pack(side=tk.LEFT)
        ttk.Entry(headers_edit_frame, textvariable=self.header_name).pack(side=tk.LEFT, padx=2)
        ttk.Label(headers_edit_frame, text="值模式:").pack(side=tk.LEFT)
        ttk.Entry(headers_edit_frame, textvariable=self.header_pattern).pack(side=tk.LEFT, padx=2)
        
        headers_btn_frame = ttk.Frame(self.headers_frame)
        headers_btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(headers_btn_frame, text="添加", command=self.add_header).pack(side=tk.LEFT, padx=2)
        ttk.Button(headers_btn_frame, text="删除", command=self.delete_header).pack(side=tk.LEFT, padx=2)

        # Form Data验证标签页
        self.form_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.form_frame, text='Form Data验证')
        
        # Form Data验证选项
        self.form_type = tk.StringVar(value="none")
        ttk.Radiobutton(self.form_frame, text="不验证", variable=self.form_type, 
                       value="none").pack(anchor=tk.W)
        ttk.Radiobutton(self.form_frame, text="必需字段", variable=self.form_type, 
                       value="required").pack(anchor=tk.W)
        
        # Form字段列表
        form_list_frame = ttk.Frame(self.form_frame)
        form_list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        columns = ('字段名', '类型', '是否必需')
        self.form_tree = ttk.Treeview(form_list_frame, columns=columns, show='headings')
        for col in columns:
            self.form_tree.heading(col, text=col)
            self.form_tree.column(col, width=100)
        self.form_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Form字段编辑区域
        form_edit_frame = ttk.Frame(self.form_frame)
        form_edit_frame.pack(fill=tk.X, pady=5)
        
        self.field_name = tk.StringVar()
        self.field_type = tk.StringVar(value="string")
        self.field_required = tk.BooleanVar(value=True)
        
        ttk.Label(form_edit_frame, text="字段名:").pack(side=tk.LEFT)
        ttk.Entry(form_edit_frame, textvariable=self.field_name).pack(side=tk.LEFT, padx=2)
        ttk.Label(form_edit_frame, text="类型:").pack(side=tk.LEFT)
        ttk.Combobox(form_edit_frame, textvariable=self.field_type, 
                    values=["string", "number", "file"]).pack(side=tk.LEFT, padx=2)
        ttk.Checkbutton(form_edit_frame, text="必需", 
                       variable=self.field_required).pack(side=tk.LEFT, padx=2)
        
        form_btn_frame = ttk.Frame(self.form_frame)
        form_btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(form_btn_frame, text="添加", command=self.add_form_field).pack(side=tk.LEFT, padx=2)
        ttk.Button(form_btn_frame, text="删除", command=self.delete_form_field).pack(side=tk.LEFT, padx=2)

    def insert_example_schema(self):
        example_schema = {
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
        self.schema_editor.set_text(json.dumps(example_schema, indent=2))

    def get_validation_config(self):
        """获取所有验证配置"""
        config = {
            'json': {
                'type': self.json_type.get(),
                'schema': None
            },
            'headers': {
                'type': self.headers_type.get(),
                'required': []
            },
            'form': {
                'type': self.form_type.get(),
                'fields': []
            }
        }
        
        # 获取JSON验证配置
        if self.json_type.get() == 'json_schema':
            try:
                schema_text = self.schema_editor.get_text()
                if schema_text.strip():
                    # 验证schema是否为有效的JSON
                    json.loads(schema_text)
                    config['json']['schema'] = schema_text
            except:
                pass
        
        # 获取Headers验证配置
        if self.headers_type.get() == 'required':
            config['headers']['required'] = [
                {'name': self.headers_tree.item(item)['values'][0],
                 'pattern': self.headers_tree.item(item)['values'][1]}
                for item in self.headers_tree.get_children()
            ]
        
        # 获取Form验证配置
        if self.form_type.get() == 'required':
            config['fields'] = [
                {'name': self.form_tree.item(item)['values'][0],
                 'type': self.form_tree.item(item)['values'][1],
                 'required': self.form_tree.item(item)['values'][2] == '是'}
                for item in self.form_tree.get_children()
            ]
        
        return config

    def set_validation_config(self, config):
        """设置验证配置"""
        if not config:
            return
            
        # 设置JSON验证
        if 'json' in config:
            self.json_type.set(config['json']['type'])
            if config['json']['schema']:
                self.schema_editor.set_text(config['json']['schema'])
                
        # 设置Headers验证
        if 'headers' in config:
            self.headers_type.set(config['headers']['type'])
            self.headers_tree.delete(*self.headers_tree.get_children())
            for header in config['headers'].get('required', []):
                self.headers_tree.insert('', tk.END, values=(header['name'], header['pattern']))
                
        # 设置Form验证
        if 'form' in config:
            self.form_type.set(config['form']['type'])
            self.form_tree.delete(*self.form_tree.get_children())
            for field in config['form'].get('fields', []):
                self.form_tree.insert('', tk.END, 
                                    values=(field['name'], field['type'], 
                                           '是' if field['required'] else '否'))

    def add_header(self):
        """添加请求头部验证规则"""
        name = self.header_name.get().strip()
        pattern = self.header_pattern.get().strip()
        if name and pattern:
            # 检查是否已存在
            for item in self.headers_tree.get_children():
                if self.headers_tree.item(item)['values'][0] == name:
                    self.headers_tree.delete(item)
            self.headers_tree.insert('', tk.END, values=(name, pattern))
            self.header_name.set('')
            self.header_pattern.set('')

    def delete_header(self):
        """删除请求头部验证规则"""
        selected = self.headers_tree.selection()
        if selected:
            self.headers_tree.delete(selected[0])

    def add_form_field(self):
        """添加表单字段验证规则"""
        name = self.field_name.get().strip()
        field_type = self.field_type.get()
        required = self.field_required.get()
        if name and field_type:
            # 检查是否已存在
            for item in self.form_tree.get_children():
                if self.form_tree.item(item)['values'][0] == name:
                    self.form_tree.delete(item)
            self.form_tree.insert('', tk.END, 
                                values=(name, field_type, '是' if required else '否'))
            self.field_name.set('')
            self.field_type.set('string')
            self.field_required.set(True)

    def delete_form_field(self):
        """删除表单字段验证规则"""
        selected = self.form_tree.selection()
        if selected:
            self.form_tree.delete(selected[0])

class HeadersManager(ttk.LabelFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, text="响应头部", **kwargs)
        self.headers = {}
        self.create_widgets()

    def create_widgets(self):
        # 头部列表框架
        list_frame = ttk.Frame(self)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 创建表格
        columns = ('名称', '值')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings')
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # 编辑区域
        edit_frame = ttk.Frame(self)
        edit_frame.pack(fill=tk.X, pady=5)
        
        self.name_var = tk.StringVar()
        self.value_var = tk.StringVar()
        
        ttk.Label(edit_frame, text="名称:").pack(side=tk.LEFT)
        ttk.Entry(edit_frame, textvariable=self.name_var, width=20).pack(side=tk.LEFT, padx=2)
        ttk.Label(edit_frame, text="值:").pack(side=tk.LEFT)
        ttk.Entry(edit_frame, textvariable=self.value_var, width=30).pack(side=tk.LEFT, padx=2)
        
        # 按钮
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame, text="添加/更新", command=self.add_header).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="删除", command=self.delete_header).pack(side=tk.LEFT, padx=2)
        
        # 绑定选择事件
        self.tree.bind('<<TreeviewSelect>>', self.on_select)

    def add_header(self):
        name = self.name_var.get().strip()
        value = self.value_var.get().strip()
        if name and value:
            self.headers[name] = value
            # 检查是否已存在
            for item in self.tree.get_children():
                if self.tree.item(item)['values'][0] == name:
                    self.tree.delete(item)
            self.tree.insert('', tk.END, values=(name, value))
            self.name_var.set('')
            self.value_var.set('')

    def delete_header(self):
        selected = self.tree.selection()
        if selected:
            item = selected[0]
            name = self.tree.item(item)['values'][0]
            self.headers.pop(name, None)
            self.tree.delete(item)

    def on_select(self, event):
        selected = self.tree.selection()
        if selected:
            item = selected[0]
            name, value = self.tree.item(item)['values']
            self.name_var.set(name)
            self.value_var.set(value)

    def get_headers(self):
        return self.headers

    def set_headers(self, headers):
        self.headers = headers.copy()
        self.tree.delete(*self.tree.get_children())
        for name, value in self.headers.items():
            self.tree.insert('', tk.END, values=(name, value))

class HTTPServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("HTTP服务端模拟器")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Flask应用
        self.app = Flask(__name__)
        # 添加CORS支持
        self.app.config['CORS_HEADERS'] = 'Content-Type'
        # 禁用Flask的默认日志
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
        
        self.server = None
        self.api_configs = []
        
        # 初始化数据库
        self.init_database()
        
        self.create_gui()
        self.setup_flask_routes()
        
        # 加载已保存的API配置
        self.load_api_configs()
        
        # 添加窗口关闭事件处理
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # 添加方法变更事件
        self.method_var.trace_remove('w', self.method_trace) if hasattr(self, 'method_trace') else None
        self.method_trace = self.method_var.trace('w', self.on_method_change)

    def init_database(self):
        self.conn = sqlite3.connect('api_configs.db')
        self.cursor = self.conn.cursor()
        
        # 检查表是否存在
        self.cursor.execute('''
            SELECT name FROM sqlite_master WHERE type='table' AND name='api_configs'
        ''')
        if self.cursor.fetchone() is None:
            # 如果表不存在，创建新表
            self.cursor.execute('''
                CREATE TABLE api_configs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT NOT NULL,
                    method TEXT NOT NULL,
                    content_type TEXT NOT NULL,
                    response_content TEXT NOT NULL,
                    request_schema TEXT,
                    response_headers TEXT
                )
            ''')
        else:
            # 如果表存在，检查并添加新列
            self.cursor.execute('PRAGMA table_info(api_configs)')
            columns = [column[1] for column in self.cursor.fetchall()]
            
            if 'request_schema' not in columns:
                self.cursor.execute('ALTER TABLE api_configs ADD COLUMN request_schema TEXT')
            
            if 'response_headers' not in columns:
                self.cursor.execute('ALTER TABLE api_configs ADD COLUMN response_headers TEXT')
        
        self.conn.commit()

    def create_gui(self):
        # 创建主框架
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 左侧API列表
        left_frame = ttk.LabelFrame(main_frame, text="API列表")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.api_listbox = tk.Listbox(left_frame)
        self.api_listbox.pack(fill=tk.BOTH, expand=True)
        self.api_listbox.bind('<<ListboxSelect>>', self.on_select_api)

        # 右侧配置区域
        right_frame = ttk.LabelFrame(main_frame, text="API配置")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 创建Notebook
        notebook = ttk.Notebook(right_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        # 基本配置标签页
        basic_frame = ttk.Frame(notebook)
        notebook.add(basic_frame, text='基本配置')

        # 服务器控制区域
        server_frame = ttk.Frame(basic_frame)
        server_frame.pack(fill=tk.X, pady=5)
        
        self.port_var = tk.StringVar(value="5000")
        ttk.Label(server_frame, text="端口:").pack(side=tk.LEFT)
        ttk.Entry(server_frame, textvariable=self.port_var, width=10).pack(side=tk.LEFT, padx=5)
        
        self.server_button = ttk.Button(server_frame, text="启动服务器", command=self.toggle_server)
        self.server_button.pack(side=tk.LEFT, padx=5)

        # API基本信息
        ttk.Label(basic_frame, text="API路径:").pack(anchor=tk.W)
        self.path_entry = ttk.Entry(basic_frame)
        self.path_entry.pack(fill=tk.X)

        # HTTP方法选择
        ttk.Label(basic_frame, text="HTTP方法:").pack(anchor=tk.W)
        self.method_var = tk.StringVar(value="GET")
        methods = ["GET", "POST", "PUT", "DELETE"]
        method_frame = ttk.Frame(basic_frame)
        method_frame.pack(fill=tk.X)
        for method in methods:
            ttk.Radiobutton(method_frame, text=method, variable=self.method_var, value=method).pack(side=tk.LEFT)

        # 响应内容类型
        ttk.Label(basic_frame, text="响应内容类型:").pack(anchor=tk.W)
        self.content_type_var = tk.StringVar(value="application/json")
        content_types = ["application/json", "application/xml", "text/plain"]
        self.content_type_combo = ttk.Combobox(basic_frame, values=content_types, textvariable=self.content_type_var)
        self.content_type_combo.pack(fill=tk.X)

        # 响应内容标签页
        response_frame = ttk.Frame(notebook)
        notebook.add(response_frame, text='响应内容')
        
        self.response_editor = JSONEditor(response_frame)
        self.response_editor.pack(fill=tk.BOTH, expand=True)

        # 响应头部标签页
        headers_frame = ttk.Frame(notebook)
        notebook.add(headers_frame, text='响应头部')
        
        self.headers_manager = HeadersManager(headers_frame)
        self.headers_manager.pack(fill=tk.BOTH, expand=True)

        # 请求验证标签页
        validation_frame = ttk.Frame(notebook)
        notebook.add(validation_frame, text='请求验证')
        
        self.params_frame = RequestParamsFrame(validation_frame)
        self.params_frame.pack(fill=tk.BOTH, expand=True)

        # 按钮区域放在基本配置页面底部
        button_frame = ttk.Frame(basic_frame)
        button_frame.pack(fill=tk.X, pady=5)

        ttk.Button(button_frame, text="添加/更新API", command=self.add_or_update_api).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="删除API", command=self.delete_api).pack(side=tk.LEFT, padx=5)

    def setup_flask_routes(self):
        @self.app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
        @self.app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
        def handle_request(path):
            print(f"收到请求:")
            print(f"- 方法: {request.method}")
            print(f"- 路径: /{path}")
            print(f"- Headers: {dict(request.headers)}")
            print(f"- Form Data: {request.form}")
            print(f"- JSON Data: {request.get_json(silent=True)}")
            
            request_path = f"/{path}" if path else "/"
            
            matching_configs = [config for config in self.api_configs if config['path'] == request_path]
            
            if matching_configs:
                method_config = next((config['method_configs'][request.method] 
                                    for config in matching_configs 
                                    if request.method in config['methods']), None)
                
                if method_config:
                    try:
                        # 获取验证配置
                        validation_config = None
                        if method_config.get('request_schema'):
                            try:
                                validation_config = json.loads(method_config['request_schema'])
                                print(f"验证配置: {validation_config}")  # 调试信息
                            except Exception as e:
                                print(f"解析验证配置失败: {str(e)}")
                        
                        if validation_config:
                            # 1. 验证Headers
                            if validation_config.get('headers', {}).get('type') == 'required':
                                required_headers = validation_config['headers'].get('required', [])
                                for header in required_headers:
                                    header_name = header['name']
                                    expected_value = header['pattern']
                                    if header_name not in request.headers:
                                        return Response(
                                            json.dumps({
                                                "error": f"缺少必需的Header: {header_name}"
                                            }),
                                            status=400,
                                            mimetype='application/json'
                                        )
                                    header_value = request.headers.get(header_name)
                                    if expected_value and header_value != expected_value:
                                        return Response(
                                            json.dumps({
                                                "error": f"Header {header_name} 的值不正确，应该是 {expected_value}"
                                            }),
                                            status=400,
                                            mimetype='application/json'
                                        )
                            
                            # 2. 验证Form Data
                            if validation_config.get('form', {}).get('type') == 'required':
                                required_fields = validation_config['form'].get('fields', [])
                                print(f"需要验证的Form字段: {required_fields}")  # 调试信息
                                for field in required_fields:
                                    if field.get('required'):
                                        field_name = field['name']
                                        field_type = field['type']
                                        if field_name not in request.form:
                                            return Response(
                                                json.dumps({
                                                    "error": f"缺少必需的表单字段: {field_name}"
                                                }),
                                                status=400,
                                                mimetype='application/json'
                                            )
                                        # 验证字段类型
                                        value = request.form[field_name]
                                        if field_type == 'number' and not value.replace('.', '').isdigit():
                                            return Response(
                                                json.dumps({
                                                    "error": f"表单字段 {field_name} 必须是数字"
                                                }),
                                                status=400,
                                                mimetype='application/json'
                                            )
                            
                            # 3. 验证JSON
                            if validation_config.get('json', {}).get('type') == 'json_schema':
                                json_schema = validation_config['json'].get('schema')
                                if json_schema:
                                    print(f"JSON Schema: {json_schema}")  # 调试信息
                                    try:
                                        schema = json.loads(json_schema)
                                        json_data = request.get_json(silent=True)
                                        
                                        # 检查Content-Type
                                        if not request.is_json:
                                            return Response(
                                                json.dumps({
                                                    "error": "请求的Content-Type必须是application/json"
                                                }),
                                                status=400,
                                                mimetype='application/json'
                                            )
                                        
                                        # 检查是否有JSON数据
                                        if json_data is None:
                                            return Response(
                                                json.dumps({
                                                    "error": "请求体必须是有效的JSON数据"
                                                }),
                                                status=400,
                                                mimetype='application/json'
                                            )
                                        
                                        # 验证JSON数据
                                        try:
                                            jsonschema.validate(json_data, schema)
                                        except jsonschema.exceptions.ValidationError as e:
                                            return Response(
                                                json.dumps({
                                                    "error": "JSON数据验证失败",
                                                    "details": str(e)
                                                }),
                                                status=400,
                                                mimetype='application/json'
                                            )
                                    except json.JSONDecodeError as e:
                                        print(f"Schema JSON解析错误: {str(e)}")
                                        return Response(
                                            json.dumps({
                                                "error": "Schema格式错误"
                                            }),
                                            status=500,
                                            mimetype='application/json'
                                        )
                                        return Response(
                                            json.dumps({
                                                "error": f"JSON验证错误: {str(e)}"
                                            }),
                                            status=500,
                                            mimetype='application/json'
                                        )

                        # 验证通过后处理响应
                        response_content = method_config['response_content']
                        if method_config['content_type'] == 'application/json':
                            try:
                                response_content = json.dumps(json.loads(response_content))
                            except:
                                pass

                        response = Response(
                            response_content,
                            mimetype=method_config['content_type']
                        )

                        # 添加响应头部
                        if method_config.get('response_headers'):
                            headers = json.loads(method_config['response_headers'])
                            for name, value in headers.items():
                                response.headers[name] = value

                        return response

                    except Exception as e:
                        print(f"处理请求时出错: {str(e)}")
                        return Response(
                            json.dumps({"error": f"服务器内部错误: {str(e)}"}),
                            status=500,
                            mimetype='application/json'
                        )

    def add_or_update_api(self):
        path = self.path_entry.get()
        if not path.startswith('/'):
            path = f"/{path}"
        
        method = self.method_var.get()
        content_type = self.content_type_var.get()
        response_content = self.response_editor.get_text()
        
        # 获取请验证配置
        validation_config = self.params_frame.get_validation_config()
        request_schema = json.dumps(validation_config) if validation_config else None
        
        # 获取响应头部配置
        response_headers = json.dumps(self.headers_manager.get_headers())
        
        print("保存配置:")  # 添加调试信息
        print(f"- 验证配置: {request_schema}")
        print(f"- 响应头部: {response_headers}")
        
        # 检查是否已存在相同路径的API
        self.cursor.execute('SELECT id, method FROM api_configs WHERE path = ? AND method = ?', (path, method))
        existing = self.cursor.fetchone()
        
        if existing:
            # 更新现有记录
            self.cursor.execute('''
                UPDATE api_configs 
                SET content_type = ?, 
                    response_content = ?, 
                    request_schema = ?, 
                    response_headers = ?
                WHERE path = ? AND method = ?
            ''', (content_type, response_content, request_schema, response_headers, path, method))
            messagebox.showinfo("成功", f"API {method} {path} 更新成功！")
        else:
            # 插入新记录
            self.cursor.execute('''
                INSERT INTO api_configs 
                (path, method, content_type, response_content, request_schema, response_headers)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (path, method, content_type, response_content, request_schema, response_headers))
            messagebox.showinfo("成功", f"API {method} {path} 添加成功！")
        
        self.conn.commit()
        self.load_api_configs()

    def delete_api(self):
        selection = self.api_listbox.curselection()
        if selection:
            index = selection[0]
            config = self.api_configs[index]
            self.cursor.execute('DELETE FROM api_configs WHERE path = ?', (config['path'],))
            self.conn.commit()
            self.load_api_configs()
            messagebox.showinfo("成功", "API删除成功！")

    def refresh_api_list(self):
        self.api_listbox.delete(0, tk.END)
        for config in self.api_configs:
            methods = ', '.join(config['methods'])
            self.api_listbox.insert(tk.END, f"{methods} {config['path']}")

    def on_select_api(self, event):
        # 先清除所有验证配置
        self.params_frame.set_validation_config(None)
        self.headers_manager.set_headers({})
        
        selection = self.api_listbox.curselection()
        if selection:
            config = self.api_configs[selection[0]]
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, config['path'])
            
            # 获取选中的方法对应的配置
            method = config['methods'][0]  # 默认选择第一个方法
            method_config = config['method_configs'][method]
            
            self.method_var.set(method)
            self.content_type_var.set(method_config['content_type'])
            self.response_editor.set_text(method_config['response_content'])
            
            # 加载请求验证配置
            if method_config.get('request_schema'):
                try:
                    validation_config = json.loads(method_config['request_schema'])
                    self.params_frame.set_validation_config(validation_config)
                except:
                    pass
            
            # 加载响应头部配置
            if method_config.get('response_headers'):
                try:
                    headers = json.loads(method_config['response_headers'])
                    self.headers_manager.set_headers(headers)
                except:
                    pass

    def toggle_server(self):
        if self.server is None:
            try:
                port = int(self.port_var.get())
                # 先检查端口是否被占用
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                
                if result == 0:
                    messagebox.showerror("错误", f"端口 {port} 已被占用")
                    return
                
                try:
                    # 修改host为0.0.0.0，允许所有IP访问
                    self.server = make_server('0.0.0.0', port, self.app, threaded=True)
                    self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
                    self.server_thread.start()
                    self.server_button.config(text="停止服务器")
                    messagebox.showinfo("成功", f"服务器已启动在端口 {port}")
                except PermissionError:
                    messagebox.showerror("错误", f"没有权限使用端口 {port}，请尝试使用1024以上的端口")
                except Exception as e:
                    print(f"启动服务器失败: {str(e)}")
                    messagebox.showerror("错误", f"启动服务器失败: {str(e)}")
            except ValueError:
                messagebox.showerror("错误", "请输入有效的端口号")
            except Exception as e:
                print(f"启动服务器时发生错误: {str(e)}")
                messagebox.showerror("错误", f"启动服务器失败: {str(e)}")
        else:
            try:
                # 先禁用按钮，防止重复点击
                self.server_button.config(state='disabled')
                
                def shutdown_server():
                    try:
                        print("正在关闭服务器...")
                        if self.server:
                            try:
                                self.server.shutdown()
                            except Exception as e:
                                print(f"关闭服务器时出错 (shutdown): {str(e)}")
                            
                            try:
                                self.server.server_close()
                            except Exception as e:
                                print(f"关闭服务器时出错 (server_close): {str(e)}")
                            
                            print("服务器已关闭")
                        
                        self.server = None
                        self.server_thread = None
                        
                        # 在主线程中更新GUI
                        self.root.after(0, lambda: self.server_button.config(text="启动服务器", state='normal'))
                        self.root.after(0, lambda: messagebox.showinfo("成功", "服务器已停止"))
                    except Exception as e:
                        print(f"关闭服务器时出错: {str(e)}")
                        self.root.after(0, lambda: self.server_button.config(state='normal'))
                        self.root.after(0, lambda: messagebox.showerror("错误", f"停止服务器失败: {str(e)}"))

                threading.Thread(target=shutdown_server, daemon=True).start()
            except Exception as e:
                print(f"创建关闭线程失败: {str(e)}")
                self.server_button.config(state='normal')
                messagebox.showerror("错误", f"停止服务器失败: {str(e)}")

    def load_api_configs(self):
        self.cursor.execute('''
            SELECT path, method, content_type, response_content, 
                   request_schema, response_headers 
            FROM api_configs
        ''')
        rows = self.cursor.fetchall()
        
        # 使用字典来按路径和方法分组
        configs_by_path = {}
        for row in rows:
            path, method, content_type, response_content, request_schema, response_headers = row
            if path not in configs_by_path:
                configs_by_path[path] = {
                    'path': path,
                    'methods': [],
                    'method_configs': {}  # 存储每个方法的独立配置
                }
            configs_by_path[path]['methods'].append(method)
            # 为每个方法存储独立的配置
            configs_by_path[path]['method_configs'][method] = {
                'content_type': content_type,
                'response_content': response_content,
                'request_schema': request_schema,
                'response_headers': response_headers
            }
        
        self.api_configs = list(configs_by_path.values())
        self.refresh_api_list()

    def on_closing(self):
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except:
                pass
        self.root.destroy()

    def __del__(self):
        if hasattr(self, 'conn'):
            self.conn.close()

    def on_method_change(self, *args):
        # 先清除所有验证配置
        self.params_frame.set_validation_config(None)
        self.headers_manager.set_headers({})
        
        selection = self.api_listbox.curselection()
        if selection:
            config = self.api_configs[selection[0]]
            method = self.method_var.get()
            if method in config['method_configs']:
                method_config = config['method_configs'][method]
                self.content_type_var.set(method_config['content_type'])
                self.response_editor.set_text(method_config['response_content'])
                
                # 更新验证配置
                if method_config.get('request_schema'):
                    try:
                        validation_config = json.loads(method_config['request_schema'])
                        self.params_frame.set_validation_config(validation_config)
                    except:
                        pass
                
                # 更新响应头部
                if method_config.get('response_headers'):
                    try:
                        headers = json.loads(method_config['response_headers'])
                        self.headers_manager.set_headers(headers)
                    except:
                        pass

if __name__ == '__main__':
    root = tk.Tk()
    app = HTTPServerGUI(root)
    root.mainloop()