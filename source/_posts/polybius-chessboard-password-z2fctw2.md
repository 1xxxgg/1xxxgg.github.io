---
title: Polybius棋盘密码
date: '2023-10-15 18:56:37'
updated: '2023-12-30 20:27:26'
permalink: /post/polybius-chessboard-password-z2fctw2.html
comments: true
toc: true
---

# Polybius棋盘密码

### 原理

Polybius密码又称为棋盘密码，其一般是将给定的明文加密为两两组合的数字，其常用密码表

||1|2|3|4|5|
| -| -| -| -| ---| -|
|1|A|B|C|D|E|
|2|F|G|H|I/J|K|
|3|L|M|N|O|P|
|4|Q|R|S|T|U|
|5|V|W|X|Y|Z|

举个例子，明文 HELLO，加密后就是 23 15 31 31 34。
另一种密码表

||A|D|F|G|X|
| -| -| -| -| -| -|
|A|b|t|a|l|p|
|D|d|h|o|z|k|
|F|q|f|v|s|n|
|G|g|j|c|u|x|
|X|m|r|e|w|y|

注意，这里字母的顺序被打乱了。
A D F G X 的由来：
1918 年，第一次世界大战将要结束时，法军截获了一份德军电报，电文中的所有单词都由 A、D、F、G、X 五个字母拼成，因此被称为 ADFGX 密码。ADFGX 密码是 1918 年 3 月由德军上校 Fritz Nebel 发明的，是结合了 Polybius 密码和置换密码的双重加密方案。
举个例子，HELLO，使用这个表格加密，就是 DD XF AG AG DF。

### 工具

- CrypTool
