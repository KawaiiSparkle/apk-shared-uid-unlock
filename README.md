# apk-shared-uid-unlock

**Android \`android.uid.system\` 特权应用的脱壳前置流程**

中文 | [English](./README.en.md)

---

## 一句话

把平台签名独占的 \`sharedUserId\` 做**等长**替换，让原来根本装不上的特权应用在普通签名设备上装得上、起得来 —— 只有进程真的跑起来，壳的解密逻辑才有机会执行，后面才有东西可脱。

这个仓库只做**前置那一段**：安装 → 启动 → 从运行内存取出代码。它不包含、也不依赖任何特定厂商或特定壳的知识。

## 问题在哪

很多厂商内置应用在 Manifest 里声明：

\`\`\`xml
<manifest android:sharedUserId="android.uid.system" ...>
\`\`\`

这段声明的含义是"我要加入系统 UID 的共享用户组"。系统在**安装期**就会校验：只有平台签名（与系统镜像同证书）的包才允许加入。

于是任何非平台签名的副本（自己重签的、从别处拿到的）都会在安装阶段被直接拒绝：

\`\`\`
INSTALL_FAILED_SHARED_USER_INCOMPATIBLE
\`\`\`

注意这一步甚至不涉及运行逻辑：包没装上，进程不存在，静态看到的只是壳的外层，动态也无从下手。

## 原理：为什么"等长替换"是安全的

二进制 \`AndroidManifest.xml\`（AXML）里的字符串存放在字符串池中，其它结构通过 **偏移 + 长度** 引用它们。只要替换后的字符串**字节数完全一致**，所有偏移和长度都不需要重算，整个文件的布局保持不变 —— 也就不需要 aapt2/apktool 反编译重建资源，不用担心资源 ID 漂移、编译产物差异。

\`\`\`
android.uid.system    (17 字节，UTF-8)
android.uid.sysadm    (17 字节，UTF-8)
\`\`\`

替换后应用以**独立的普通 UID** 运行，不再是系统共享组的一员。它能装、能起。

## 快速开始

\`\`\`bash
pip install -r requirements.txt        # 只用 --dump 时才需要 frida
export ANDROID_HOME=/path/to/android-sdk   # 或用 --build-tools 指定

# 一步到位：改 Manifest -> 重打包 -> zipalign -> 签名 -> 验签 -> 安装
python src/priv_unlock.py app.apk --install

# 装完顺手从内存里取出所有通过自校验的 dex
python src/priv_unlock.py app.apk --install --dump
\`\`\`

签名之后单独取代码：

\`\`\`bash
adb forward tcp:27042 tcp:27042        # frida-server 监听 27042
python src/dex_dump.py --package com.example.app --out dumps
\`\`\`

批量处理：

\`\`\`bash
python src/priv_unlock.py incoming/*.apk --out out/
\`\`\`

## 产物

| 文件 | 说明 |
| --- | --- |
| \`<name>_unlocked.apk\` | 改过 \`sharedUserId\` 并重新签名（v1+v2+v3）的包 |
| \`<name>_dumps/classesN.dex\` | 从运行内存取出、通过 adler32 + SHA-1 自校验的 dex |
| \`<name>_dumps/manifest.json\` | 每个 dex 的版本、string 数、class 数、SHA-1 |

判定"这是真 dex"的标准不是长度、也不是名字，而是：

\`\`\`
header_size == 0x70
endian_tag  == 0x12345678
adler32(d[12:]) == header.checksum
sha1(d[32:])    == header.signature
\`\`\`

四项全过才落盘。壳拼出来的缓冲、改动过的字节、以及巧合命中的魔数都会被丢掉。

## 适用范围与边界

**能解决**

- 安装期被 \`sharedUserId\` 拦下的应用：装得上、起得来
- 解密发生在 \`Application.attachBaseContext\` 早期（绝大多数加固方案如此）：进程存活即已解密
- 只需要"看到代码"：dump 出来的 dex 可直接交给静态分析工具

**不能解决**

- 真正依赖系统身份调用的功能：\`SecurityException\` 属预期结果（见 [docs/field-notes.md](docs/field-notes.md)）
- 与系统应用共享数据目录：改了 \`sharedUserId\` 就不再共享
- 设备上已存在同名 shared user 且证书不同：安装会报 \`INSTALL_FAILED_SHARED_USER_INCOMPATIBLE\`，需用同一把证书（\`--keystore\`）
- 强完整性校验 / 反调试 / 运行期签名自检的加固：需要另行处理，本仓库不涉及

## 前置条件

- 一台可 \`adb\` 的 Android 设备（要 dump 的话需能起 frida-server）
- Android SDK build-tools（\`zipalign\` + \`apksigner\`）
- JDK（\`keytool\`）
- 可选：\`frida\`（仅 \`--dump\`）

## 文档

- [docs/field-notes.md](docs/field-notes.md) —— 实战踩到的边界、报错原文与判断依据
- [docs/technique.md](docs/technique.md) —— AXML 字符串池、等长替换的安全条件

## 声明

本项目面向**自有设备上的兼容性测试、安全研究与教学**。请只在你拥有或已获明确授权的设备与样本上使用；不用于绕过付费、DRM 或规避任何许可机制。作者不对使用者的行为承担责任。

## License

[MIT](./LICENSE)
