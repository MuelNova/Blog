---
title: 「PWN」exit_hook 的利用与原理
authors: [nova]
tags: [CTF, Pwn, CVE]
draft: true
unlisted: true
---

### _rtld_global

> - 一次任意写 OG
> - 两次任意写 func + arg1
> - 伪造 *_rtld_global* 结构体

#### 成因

简要而言，在 *exit* 调用 *_dl_fini* 时，会调用 *_rtld_lock_lock_recursive* 和 *_rtld_lock_unlock_recursive* 进行上锁和释放。而这两个宏展开之后分别是 *\_rtld_global.\_dl_lock_lock_recursive(&\_rtld_global.\_dl_load_lock.mutex)* 和 *\_rtld_global.\_dl_lock_unlock_recursive(&\_rtld_global.\_dl_load_lock.mutex)*

#### 用法
>```
>libc-2.23 _rtld_global:0x5f0040   __rtld_lock_lock_recursive: 3848  __rtld_lock_unlock_recursive: 3856
>libc-2.27 _rtld_global:0x619060   __rtld_lock_lock_recursive: 3840  __rtld_lock_unlock_recursive: 3848
>libc-2.31 _rtld_global:0x23e060   __rtld_lock_lock_recursive: 3848  __rtld_lock_unlock_recursive: 3856
>```

修改 *\_rtld_lock_lock_recursive/\_rtld_lock_unlock_recursive* 为 OneGadget

或是修改 *_rtld_lock_lock_recursive/\_rtld_lock_unlock_recursive* 为 func，接着修改 *\_rtld_global.\_dl_load_lock.mutex* 为 arg1

