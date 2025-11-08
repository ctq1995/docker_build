# 使用 Python 3.13 作为基础镜像
FROM python:3.13-slim

# 设置工作目录
WORKDIR /app

# [关键] 安装编译工具和 Tkinter 依赖
# libx11-6 是 ttkbootstrap 运行时的隐式依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-tk \
    libx11-6 \
    && rm -rf /var/lib/apt/lists/*

# 复制项目文件
COPY __main__.py myfont.otf ./

# 安装 Python 依赖
RUN pip install --no-cache-dir -U nuitka ttkbootstrap paramiko pillow

# 执行 Nuitka 打包命令
# 使用 ARG 来接收目标平台，并据此命名输出目录
ARG TARGETPLATFORM
RUN python3 -m nuitka \
    --onefile \
    --standalone \
    --enable-plugin=tk-inter \
    --enable-plugin=pillow \
    --include-data-file=myfont.otf=myfont.otf \
    --output-dir=dist_${TARGETPLATFORM#linux/} \
    __main__.py
