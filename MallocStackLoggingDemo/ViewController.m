//
//  ViewController.m
//  MallocStackLoggingDemo
//
//  Created by styf on 2021/12/13.
//

#import "ViewController.h"
#import "Person.h"
#include <malloc/malloc.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach/mach_init.h>
#import "execinfo.h"
#import <dlfcn.h>
#include <mach/mach.h>

@interface ViewController ()
/// 日志开关
@property (nonatomic, assign) BOOL isOpen;
/// 记录一个用于观察的person对象内存地址
@property (nonatomic, assign) uint64_t personAddress;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [self deleteAllLogFile];
    
    CGFloat buttonWidth = [UIScreen mainScreen].bounds.size.width - 50;
    CGFloat buttonHeight = 50;
    CGFloat buttonX = 25;
    
    UIButton *button = [UIButton buttonWithType:UIButtonTypeCustom];
    button.frame = CGRectMake(buttonX, 100, buttonWidth, buttonHeight);
    button.backgroundColor = UIColor.greenColor;
    [button setTitle:@"turn_on_stack_logging" forState:UIControlStateNormal];
    [button addTarget:self action:@selector(my_turn_on_stack_logging) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:button];
    
    UIButton *button1 = [UIButton buttonWithType:UIButtonTypeCustom];
    button1.frame = CGRectMake(buttonX, 170, buttonWidth, buttonHeight);
    button1.backgroundColor = UIColor.greenColor;
    [button1 setTitle:@"turn_off_stack_logging" forState:UIControlStateNormal];
    [button1 addTarget:self action:@selector(my_turn_off_stack_logging) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:button1];
    
    UIButton *button2 = [UIButton buttonWithType:UIButtonTypeCustom];
    button2.frame = CGRectMake(buttonX, 240, buttonWidth, buttonHeight);
    button2.backgroundColor = UIColor.greenColor;
    [button2 setTitle:@"check_person_stacks" forState:UIControlStateNormal];
    [button2 addTarget:self action:@selector(check_person_stacks) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:button2];
    
    UIButton *button3 = [UIButton buttonWithType:UIButtonTypeCustom];
    button3.frame = CGRectMake(buttonX, 310, buttonWidth, buttonHeight);
    button3.backgroundColor = UIColor.greenColor;
    [button3 setTitle:@"analysis_last_stack_log_file" forState:UIControlStateNormal];
    [button3 addTarget:self action:@selector(analysis_last_stack_log_file) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:button3];
    
    UIButton *button4 = [UIButton buttonWithType:UIButtonTypeCustom];
    button4.frame = CGRectMake(buttonX, 380, buttonWidth, buttonHeight);
    button4.backgroundColor = UIColor.greenColor;
    [button4 setTitle:@"test_enumerate_records" forState:UIControlStateNormal];
    [button4 addTarget:self action:@selector(test_enumerate_records) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:button4];
    
    UIButton *button5 = [UIButton buttonWithType:UIButtonTypeCustom];
    button5.frame = CGRectMake(buttonX, 450, buttonWidth, buttonHeight);
    button5.backgroundColor = UIColor.greenColor;
    [button5 setTitle:@"运行时分析日志测试" forState:UIControlStateNormal];
    [button5 addTarget:self action:@selector(runtime_analysis_last_stack_log_file) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:button5];
    
    UIButton *button6 = [UIButton buttonWithType:UIButtonTypeCustom];
    button6.frame = CGRectMake(buttonX, 520, buttonWidth, buttonHeight);
    button6.backgroundColor = UIColor.greenColor;
    [button6 setTitle:@"离线分析日志测试" forState:UIControlStateNormal];
    [button6 addTarget:self action:@selector(offline_analysis_last_stack_log_file) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:button6];
    
//    [NSTimer scheduledTimerWithTimeInterval:3 target:self selector:@selector(willCreateAPerson) userInfo:nil repeats:YES];
}

//typedef enum {
//    stack_logging_mode_none = 0,
//    stack_logging_mode_all,
//    stack_logging_mode_malloc,
//    stack_logging_mode_vm,
//    stack_logging_mode_lite,
//    stack_logging_mode_vmlite
//} stack_logging_mode_type;

//extern boolean_t turn_on_stack_logging(stack_logging_mode_type mode);
extern boolean_t turn_on_stack_logging(int mode);
extern void turn_off_stack_logging(void);

- (void)my_turn_on_stack_logging {
    if (_isOpen) return;
    _isOpen = YES;
    turn_on_stack_logging(1);
//    File names are of the form stack-logs.<pid>.<address>.<progname>.XXXXXX.index
}

- (void)my_turn_off_stack_logging {
    if (!_isOpen) return;
    _isOpen = NO;
    turn_off_stack_logging();
}


#define MAX_FRAMES    512

extern kern_return_t __mach_stack_logging_get_frames(task_t task, mach_vm_address_t address, mach_vm_address_t *stack_frames_buffer, uint32_t max_stack_frames, uint32_t *count);
    /* Gets the last allocation record (malloc, realloc, or free) about address */
// 测试__mach_stack_logging_get_frames方法  创建一个Person对象，然后查一下它的分配堆栈
- (void)check_person_stacks {
    if (!_isOpen) {
        NSLog(@"❎ 还没有打开日志开关呢");
        return;
    }
    
    Person *person = [self createAPerson];
    mach_vm_address_t frames[MAX_FRAMES];
    uint32_t frames_count;
    
//    kern_return_t ret = (lite_mode) ?
//    __mach_stack_logging_get_frames_for_stackid(mach_task_self(), get_stack_id_from_ptr(person), frames, MAX_FRAMES, &frames_count, NULL) :
//    __mach_stack_logging_get_frames(mach_task_self(), (mach_vm_address_t) ptrs[i], frames, MAX_FRAMES, &frames_count);
    
    kern_return_t ret = __mach_stack_logging_get_frames(mach_task_self(), (mach_vm_address_t)person, frames, MAX_FRAMES, &frames_count);
    if (ret == KERN_SUCCESS) {
        NSLog(@"return from __mach_stack_logging_get_frames = %d\n", (int) ret);
    }
    if (frames_count > 0) {
        NSLog(@"number of frames returned from __mach_stack_logging_get_frames = %u\n", frames_count);
        
        for (int i = 0; i < frames_count; i++) {
            vm_address_t addr = frames[i];
            Dl_info info;
            dladdr((void *)addr, &info);
            NSLog(@"---  %s",info.dli_sname);
        }
    }
}

typedef struct mach_stack_logging_record {
//    uint32_t        type_flags;   我猜测这里也已经是64位了
    uint64_t        type_flags;
    uint64_t        stack_identifier;
    uint64_t        argument;
    mach_vm_address_t    address;
} my_mach_stack_logging_record_t;

extern kern_return_t __mach_stack_logging_enumerate_records(task_t task, mach_vm_address_t address, void enumerator(my_mach_stack_logging_record_t, void *), void *context);
    
void enumerate_records_hander(my_mach_stack_logging_record_t record, void * context) {
    NSString *type = typeString(record.type_flags);
    NSLog(@"%@ size:%llu stackid:0x%llx address:%p",type,record.argument,record.stack_identifier,(void *)record.address);
}

- (void)test_enumerate_records {
    if (!_isOpen) {
        NSLog(@"❎ 还没有打开日志开关呢");
        return;
    }
    __mach_stack_logging_enumerate_records(mach_task_self(), NULL, enumerate_records_hander, NULL);
}

//❌这是以前的版本了
typedef struct {
    uintptr_t argument; //大小
    uintptr_t address; //伪装后的内存地址
    uint64_t offset_and_flags; // top 8 bits are actually the flags!
    //    (16个0_stack_id的低48位) | (type_flags的低8位_56个0 ) | (type_flags的24-32位_48个0) = type_flags的低8位_type_flags的24-32位_stack_id的低48位 = 共64位
} my_stack_logging_index_event;

//❌ 第二次错误尝试
typedef struct {
    uint64_t argument;
    uint64_t address;
    uint64_t offset_and_flags;
    uint64_t what;
} wrong_stack_logging_index_event64;

//✅ 这是现在的版本了
typedef struct {
    uint64_t argument;
    uint64_t address;
    uint64_t offset;
    uint64_t flags;
} test_stack_logging_index_event64;

#define STACK_LOGGING_DISGUISE(address)    ((address) ^ 0x00005555) /* nicely idempotent */

#define STACK_LOGGING_FLAGS_SHIFT 56
#define STACK_LOGGING_USER_TAG_SHIFT 24
#define STACK_LOGGING_FLAGS(longlongvar) (uint32_t)((uint64_t)(longlongvar) >> STACK_LOGGING_FLAGS_SHIFT)
#define STACK_LOGGING_FLAGS_AND_USER_TAG(longlongvar) \
    (uint32_t)(STACK_LOGGING_FLAGS(longlongvar) | (((uint64_t)(longlongvar)&0x00FF000000000000ull) >> STACK_LOGGING_USER_TAG_SHIFT))
// (56个0_longlongvar高8位) | (longlongvar)
#define STACK_LOGGING_OFFSET_MASK 0x0000FFFFFFFFFFFFull
#define STACK_LOGGING_OFFSET(longlongvar) ((longlongvar)&STACK_LOGGING_OFFSET_MASK)

#define STACK_LOGGING_OFFSET_AND_FLAGS(longlongvar, type_flags)                                                    \
    (((uint64_t)(longlongvar)&STACK_LOGGING_OFFSET_MASK) | ((uint64_t)(type_flags) << STACK_LOGGING_FLAGS_SHIFT) | \
            (((uint64_t)(type_flags)&0xFF000000ull) << STACK_LOGGING_USER_TAG_SHIFT))

/// 分析一下刚刚的日志文件
- (void)analysis_last_stack_log_file {
    if (_isOpen) {
        NSLog(@"❎ 先把日志关了吧");
        return;
    }
    NSString *filePath = [self lastLogFilePath];
    if (!filePath.length) {
        NSLog(@"❎ 找不到日志呢");
        return;
    }
    NSLog(@"获取到刚刚的日志文件：%@",filePath);
    const char *path = [filePath cStringUsingEncoding:4];
    FILE *fp = fopen(path,  "r");
    
    
    //❌ 错误1
//    char bufferSpace[4096];
//    size_t read_count = 0;
//    size_t read_size = sizeof(my_stack_logging_index_event);
//    size_t number_slots = (size_t)(4096 / read_size);
//
//    if (fp != NULL) {
//        do {
//            read_count = fread(bufferSpace, read_size, number_slots, fp);
//            if (read_count > 0) {
//                my_stack_logging_index_event *target_64_index = (my_stack_logging_index_event *)bufferSpace;
//                for (int i = 0; i < read_count; i++) {
//                    my_stack_logging_index_event index_event = target_64_index[i];
//                    my_mach_stack_logging_record_t pass_record;
//                    pass_record.address = STACK_LOGGING_DISGUISE(index_event.address);
//                    pass_record.argument = target_64_index[i].argument;
//                    pass_record.stack_identifier = STACK_LOGGING_OFFSET(index_event.offset_and_flags);
//                    pass_record.type_flags = STACK_LOGGING_FLAGS_AND_USER_TAG(index_event.offset_and_flags);
//
//                    NSString *type = typeString(pass_record.type_flags);
//                    NSLog(@"%@ size:%llu stackid:0x%llx address:%p",type,pass_record.argument,pass_record.stack_identifier,(void *)pass_record.address);
//                }
//            }
//        } while (read_count > 0);
//        fclose(fp);
//    }
 
//    //❌ 错误2
//    char bufferSpace[4096];
//    size_t read_count = 0;
//    size_t read_size = sizeof(wrong_stack_logging_index_event64);
//    size_t number_slots = (size_t)(4096 / read_size);
//
//    if (fp != NULL) {
//        do {
//            read_count = fread(bufferSpace, read_size, number_slots, fp);
//            if (read_count > 0) {
//                wrong_stack_logging_index_event64 *target_64_index = (wrong_stack_logging_index_event64 *)bufferSpace;
//                for (int i = 0; i < read_count; i++) {
//                    wrong_stack_logging_index_event64 index_event = target_64_index[i];
//                    my_mach_stack_logging_record_t pass_record;
//                    pass_record.address = STACK_LOGGING_DISGUISE(index_event.address);
//                    pass_record.argument = target_64_index[i].argument;
//                    pass_record.stack_identifier = STACK_LOGGING_OFFSET(index_event.offset_and_flags);
//                    pass_record.type_flags = STACK_LOGGING_FLAGS_AND_USER_TAG(index_event.offset_and_flags);
//
//                    NSString *type = typeString(pass_record.type_flags);
//                    NSLog(@"%@ size:%llu stackid:0x%llx address:%p",type,pass_record.argument,pass_record.stack_identifier,(void *)pass_record.address);
//                }
//            }
//        } while (read_count > 0);
//        fclose(fp);
//    }
    
      //✅ 正确
    char bufferSpace[4096];
    size_t read_count = 0;
    size_t read_size = sizeof(test_stack_logging_index_event64);
    size_t number_slots = (size_t)(4096 / read_size);

    if (fp != NULL) {
        do {
            read_count = fread(bufferSpace, read_size, number_slots, fp);
            if (read_count > 0) {
                test_stack_logging_index_event64 *target_64_index = (test_stack_logging_index_event64 *)bufferSpace;
                for (int i = 0; i < read_count; i++) {
                    test_stack_logging_index_event64 index_event = target_64_index[i];
                    my_mach_stack_logging_record_t pass_record;
                    pass_record.address = STACK_LOGGING_DISGUISE(index_event.address);
                    pass_record.argument = target_64_index[i].argument;
                    pass_record.stack_identifier = index_event.offset;
                    pass_record.type_flags = index_event.flags;

                    NSString *type = typeString(pass_record.type_flags);
                    NSLog(@"%@ size:%llu stackid:0x%llx address:%p",type,pass_record.argument,pass_record.stack_identifier,(void *)pass_record.address);
                }
            }
        } while (read_count > 0);
        fclose(fp);
    }
}

///运行时分析日志
- (void)runtime_analysis_last_stack_log_file {
    if (_isOpen) {
        NSLog(@"❎ 日志开关已经打开了，先关闭，并保证只有一个日志文件");
        return;
    }
    //先打开开关
    [self my_turn_on_stack_logging];
    
    
    //先建个200个对象，防止数据太少，还没触发MallocStackLogging的写入操作
    NSMutableArray *array = [NSMutableArray array];
    for (int i = 0; i < 200; i++) {
        [array addObject:[Person new]];
    }
    //这个对象是我要观察的
    [self willCreateAPerson];
    
    //1秒后关闭日志记录系统
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        
        //关闭日志
        [self my_turn_off_stack_logging];
        
        //观察这个person对象
        [self runtime_analysis_this_person];
    });
}

extern
struct backtrace_uniquing_table *
__mach_stack_logging_copy_uniquing_table(task_t task);

extern kern_return_t
__mach_stack_logging_uniquing_table_read_stack(struct backtrace_uniquing_table *uniquing_table,
                                               uint64_t stackid,
                                               mach_vm_address_t *out_frames_buffer,
                                               uint32_t *out_frames_count,
                                               uint32_t max_frames);

extern
void
__mach_stack_logging_uniquing_table_release(struct backtrace_uniquing_table *);

- (void)runtime_analysis_this_person {
    NSString *filePath = [self lastLogFilePath];
    if (!filePath.length) {
        NSLog(@"❎ 找不到日志呢");
        return;
    }
    NSLog(@"获取到刚刚的日志文件：%@",filePath);
    const char *path = [filePath cStringUsingEncoding:4];
    FILE *fp = fopen(path,  "r");
    
    char bufferSpace[4096];
    size_t read_count = 0;
    size_t read_size = sizeof(test_stack_logging_index_event64);
    size_t number_slots = (size_t)(4096 / read_size);

    //最后一条person的内存分配记录
    my_mach_stack_logging_record_t last_person_record;
    
    if (fp != NULL) {
        do {
            read_count = fread(bufferSpace, read_size, number_slots, fp);
            if (read_count > 0) {
                test_stack_logging_index_event64 *target_64_index = (test_stack_logging_index_event64 *)bufferSpace;
                for (int i = 0; i < read_count; i++) {
                    test_stack_logging_index_event64 index_event = target_64_index[i];
                    my_mach_stack_logging_record_t pass_record;
                    pass_record.address = STACK_LOGGING_DISGUISE(index_event.address);
                    pass_record.argument = target_64_index[i].argument;
                    pass_record.stack_identifier = index_event.offset;
                    pass_record.type_flags = index_event.flags;
                    
                    NSString *type = typeString(pass_record.type_flags);
//                    NSLog(@"%@ size:%llu stackid:0x%llx address:%p",type,pass_record.argument,pass_record.stack_identifier,(void *)pass_record.address);
                    if (pass_record.address == _personAddress && [type isEqualToString:@"alloc"]) {
                        last_person_record = pass_record;
                    }
                }
            }
        } while (read_count > 0);
        fclose(fp);
    }
    
    if (last_person_record.address == _personAddress) {
        NSLog(@"找到了刚刚创建person的内存记录");
        
        //用系统api拷贝一份哈希表出来
        struct backtrace_uniquing_table *table = __mach_stack_logging_copy_uniquing_table(mach_task_self());
        if (table != NULL) {
            //用系统api 使用stack_id 查找 堆栈信息
            mach_vm_address_t frames[MAX_FRAMES];
            uint32_t frames_count;
            // 从表中查询 堆栈
            kern_return_t ret = __mach_stack_logging_uniquing_table_read_stack(table, last_person_record.stack_identifier, frames, &frames_count, MAX_FRAMES);
            if (ret == KERN_SUCCESS) {
                if (frames_count > 0) {
                    NSLog(@"number of frames returned from __mach_stack_logging_get_frames = %u\n", frames_count);
                    NSLog(@"刚刚的person对象的分配堆栈如下:");
                    for (int i = 0; i < frames_count; i++) {
                        vm_address_t addr = frames[i];
                        Dl_info info;
                        dladdr((void *)addr, &info);
                        NSLog(@"---  %s",info.dli_sname);
                    }
                }
            }else {
                NSLog(@"__mach_stack_logging_uniquing_table_read_stack 调用失败❎");
            }
            
            //释放哈希表
            __mach_stack_logging_uniquing_table_release(table);
        }
        
    }
    
}
//离线分析日志
- (void)offline_analysis_last_stack_log_file {
    if (_isOpen) {
        NSLog(@"❎ 日志开关已经打开了，先关闭，并保证只有一个日志文件");
        return;
    }
    //先打开开关
    [self my_turn_on_stack_logging];
    
    
    //先建个200个对象，防止数据太少，还没触发MallocStackLogging的写入操作
    NSMutableArray *array = [NSMutableArray array];
    for (int i = 0; i < 200; i++) {
        [array addObject:[Person new]];
    }
    //这个对象是我要观察的
    [self willCreateAPerson];
    
    //1秒后关闭日志记录系统
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        
        //关闭日志
        [self my_turn_off_stack_logging];
        
        //观察这个person对象
        [self offline_analysis_this_person];
    });
}

- (void)offline_analysis_this_person {
    NSString *filePath = [self lastLogFilePath];
    if (!filePath.length) {
        NSLog(@"❎ 找不到日志呢");
        return;
    }
    NSLog(@"获取到刚刚的日志文件：%@",filePath);
    const char *path = [filePath cStringUsingEncoding:4];
    FILE *fp = fopen(path,  "r");
    
    char bufferSpace[4096];
    size_t read_count = 0;
    size_t read_size = sizeof(test_stack_logging_index_event64);
    size_t number_slots = (size_t)(4096 / read_size);

    //最后一条person的内存分配记录
    my_mach_stack_logging_record_t last_person_record;
    
    if (fp != NULL) {
        do {
            read_count = fread(bufferSpace, read_size, number_slots, fp);
            if (read_count > 0) {
                test_stack_logging_index_event64 *target_64_index = (test_stack_logging_index_event64 *)bufferSpace;
                for (int i = 0; i < read_count; i++) {
                    test_stack_logging_index_event64 index_event = target_64_index[i];
                    my_mach_stack_logging_record_t pass_record;
                    pass_record.address = STACK_LOGGING_DISGUISE(index_event.address);
                    pass_record.argument = target_64_index[i].argument;
                    pass_record.stack_identifier = index_event.offset;
                    pass_record.type_flags = index_event.flags;
                    
                    NSString *type = typeString(pass_record.type_flags);
//                    NSLog(@"%@ size:%llu stackid:0x%llx address:%p",type,pass_record.argument,pass_record.stack_identifier,(void *)pass_record.address);
                    if (pass_record.address == _personAddress && [type isEqualToString:@"alloc"]) {
                        last_person_record = pass_record;
                    }
                }
            }
        } while (read_count > 0);
        fclose(fp);
    }
    
    if (last_person_record.address == _personAddress) {
        NSLog(@"找到了刚刚创建person的内存记录");
        
        //用系统api拷贝一份哈希表出来
        extern
        struct backtrace_uniquing_table *
        __mach_stack_logging_copy_uniquing_table(task_t task);
        
        struct backtrace_uniquing_table *table = __mach_stack_logging_copy_uniquing_table(mach_task_self());
        if (table != NULL) {
            
            // 持久化 哈希表到文件
            extern
            void *
            __mach_stack_logging_uniquing_table_serialize(struct backtrace_uniquing_table *table, mach_vm_size_t *size);
            /* Writes out a serialized representation of the table.  Free it with mach_vm_deallocate. */
            
            mach_vm_size_t table_data_size;
            char *table_data = __mach_stack_logging_uniquing_table_serialize(table, &table_data_size);
            
            bool writeSuccess = false;
            NSString *tableFilePath = [NSString stringWithFormat:@"%@mytable",NSTemporaryDirectory()];
            if (table_data_size > 0) {
                
                FILE *fp = fopen([tableFilePath cStringUsingEncoding:4],  "wb");
                
                if (fp != NULL) {
                    size_t writeSize = fwrite(table_data, sizeof(char), table_data_size/sizeof(char), fp);
                    NSLog(@"哈希表持久化成功");
                    writeSuccess = true;
                    fclose(fp);
                }
            }
            
//            mach_vm_deallocate(mach_task_self(), table_data, table_data_size);
            vm_deallocate(mach_task_self(), (vm_address_t)table_data, table_data_size);

            
            //从这里开始，假装我在离线读取分析-----------------
            
            if (writeSuccess) {
                FILE *fp = fopen([tableFilePath cStringUsingEncoding:4],  "r");
                
                if (fp != NULL) {
                    char *tableBuffer = malloc(table_data_size);
                    fread(tableBuffer, table_data_size, 1, fp);
                    
                    fclose(fp);
                    
                    //反序列化哈希表
                    extern
                    struct backtrace_uniquing_table *
                    __mach_stack_logging_uniquing_table_copy_from_serialized(void *buffer, size_t size);
                    
                    struct backtrace_uniquing_table *newTable = __mach_stack_logging_uniquing_table_copy_from_serialized(tableBuffer, table_data_size);
                    free(tableBuffer);
                    
                    if (newTable != NULL) {
                        NSLog(@"反序列化成功");
                        
                        //用系统api 使用stack_id 查找 堆栈信息
                        mach_vm_address_t frames[MAX_FRAMES];
                        uint32_t frames_count;
                        // 从表中查询 堆栈
                        kern_return_t ret = __mach_stack_logging_uniquing_table_read_stack(newTable, last_person_record.stack_identifier, frames, &frames_count, MAX_FRAMES);
                        if (ret == KERN_SUCCESS) {
                            if (frames_count > 0) {
                                NSLog(@"number of frames returned from __mach_stack_logging_get_frames = %u\n", frames_count);
                                NSLog(@"刚刚的person对象的分配堆栈如下:");
                                for (int i = 0; i < frames_count; i++) {
                                    vm_address_t addr = frames[i];
                                    Dl_info info;
                                    dladdr((void *)addr, &info);
                                    NSLog(@"---  %s",info.dli_sname);
                                }
                            }
                        }else {
                            NSLog(@"__mach_stack_logging_uniquing_table_read_stack 调用失败❎");
                        }
                    }
                }
            }
            
            //释放哈希表
            __mach_stack_logging_uniquing_table_release(table);
        }
        
    }
    
}

NSString * typeString(uint64_t type_flags) {
#define stack_logging_type_free        0
#define stack_logging_type_generic    1    /* anything that is not allocation/deallocation */
#define stack_logging_type_alloc    2    /* malloc, realloc, etc... */
#define stack_logging_type_dealloc    4    /* free, realloc, etc... */
#define stack_logging_type_vm_allocate  16      /* vm_allocate or mmap */
#define stack_logging_type_vm_deallocate  32    /* vm_deallocate or munmap */
#define stack_logging_type_mapped_file_or_shared_mem    128
    
    if (type_flags & stack_logging_type_free) return @"free";
    if (type_flags & stack_logging_type_generic) return @"generic";
    if (type_flags & stack_logging_type_alloc) return @"alloc";
    if (type_flags & stack_logging_type_dealloc) return @"dealloc";
    if (type_flags & stack_logging_type_vm_allocate) return @"vm_allocate";
    if (type_flags & stack_logging_type_vm_deallocate) return @"vm_deallocate";
    if (type_flags & stack_logging_type_mapped_file_or_shared_mem) return @"mapped_file_or_shared_mem";
    return @"unknow";
}

/// 获取一下刚刚的日志文件
- (NSString *)lastLogFilePath {
//    /private/var/mobile/Containers/Data/Application/D1726421-6DFF-45FD-917B-4C5B97C9C949/tmp/stack-logs.426.1016bc000.MallocStackLoggingDemo.Kplvj1.index
    
    NSString *tmpDirPath = NSTemporaryDirectory();
    NSFileManager *fm = [NSFileManager defaultManager];
    NSDirectoryEnumerator *dirEnum = [fm enumeratorAtPath:tmpDirPath];
    NSString *fileName;
    NSString *filePath;
    while ((fileName = [dirEnum nextObject]) != nil) {
        filePath = [NSString stringWithFormat:@"%@%@",tmpDirPath,fileName];
        break;
    }
    return filePath;
}

/// 删除所有日志
- (void)deleteAllLogFile {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *tmpDirPath = NSTemporaryDirectory();
    NSDirectoryEnumerator *dirEnum = [fm enumeratorAtPath:tmpDirPath];
    NSString *fileName;
    while ((fileName = [dirEnum nextObject]) != nil) {
        NSString *filePath = [NSString stringWithFormat:@"%@%@",tmpDirPath,fileName];
        NSError *error;
        [fm removeItemAtPath:filePath error:&error];
        if (!error) {
            NSLog(@"删除残余日志成功✅：%@",filePath);
        }else {
            NSLog(@"删除残余日志失败❌：%@",filePath);
        }
    }
}

- (void)willCreateAPerson {
    NSLog(@"will create a person");
    [self createAPerson];
}

- (Person *)createAPerson {
    static int count = 1;
    Person *p = [[Person alloc]init];
    p.name = [NSString stringWithFormat:@"zhangsan %d",count++];
    p.age = count;
    _personAddress = (uint64_t)p;
    NSLog(@"%@ is created %p",p.name,p);
    return p;
}

@end
