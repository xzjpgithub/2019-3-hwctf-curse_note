# 零碎的知识点
### 1.main_arena 与 t_arena
malloc一个很当的空间时，int_malloc会返回null<br>
从而去调用arena_get_retry分配新的arena，再次尝试去分配内存，当然最后分配也是失败的<br>
一旦分配了新的arena，之后的堆操作会使用这个arena进行操作，可以参考arena_get函数<br>
新的arena的查看，p &main_arena->next 就可以找到新的arena的地址，进行查看
![t_arena](img/t_arena.png)<br>

# 题目分析
menu题目<br>
![menu](img/menu.PNG)<br>
### 漏洞点
漏洞点在new_note的malloc地方，malloc的size没有被限制，也没有校验malloc的返回值<br>
导致`*((_BYTE *)qword_202050[v1] + size - 1) = 0;`，任意地址写0<br>
![vuln](img/vuln.PNG)<br>


## 总体思路
1.chunk块在free和malloc的时候没有对立面的内容进行清空，所以很容易可以泄露出main_arena的地址,进而获取libc的基址<br>
2.由于要使用任意地址写0这个操作，必定要malloc(big_size)，后续的操作都会在t_arena上进行。所以先将chunk移到t_arena上，然后泄露t_arena的基址<br>
