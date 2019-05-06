# 零碎的知识点
### 1.main_arena 与 t_arena
malloc一个很当的空间时，int_malloc会返回null<br>
从而去调用arena_get_retry分配新的arena，再次尝试去分配内存，当然最后分配也是失败的<br>
一旦分配了新的arena，之后的堆操作会使用这个arena进行操作，可以参考arena_get函数<br>
