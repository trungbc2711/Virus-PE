import pefile
import mmap
import os
import codecs
#hàm thêm section mới vào cuối file pe.
def add(exe_path):
    
    def align(val_to_align, alignment):
       return ((val_to_align + alignment - 1) / alignment) * alignment
    # Bước 1 - Thay đổi kích thước file pe
    # Mở rộng kích thước của file pe để thêm section mới vào
    print "[*] STEP 0x01 - Resize the Executable"

    original_size = os.path.getsize(exe_path)
    print "\t[+] Original Size = %d" % original_size
    fd = open(exe_path, 'a+b')#mở file ở dạng binary và mở rộng kích thước tới cuối file.
    map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
    map.resize(original_size + 0x2000)#mở rộng thêm 8KB cho file 
    map.close()
    fd.close()
    print "\t[+] New Size = %d bytes\n" % os.path.getsize(exe_path)

    # Bước 2 - Thêm section header mới
    #thêm section offset
    print "[*] STEP 02 - Add the New Section Header"
    pe = pefile.PE(exe_path)
    number_of_section = pe.FILE_HEADER.NumberOfSections
    last_section = number_of_section - 1
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    new_section_offset = (pe.sections[number_of_section - 1].get_file_offset() + 40)
    # Tìm giá trị hợp lệ cho section header mới
    raw_size = align(0x1000, file_alignment)
    virtual_size = align(0x1000, section_alignment)
    raw_offset = align((pe.sections[last_section].PointerToRawData +
                        pe.sections[last_section].SizeOfRawData),
                       file_alignment)

    virtual_offset = align((pe.sections[last_section].VirtualAddress +
                            pe.sections[last_section].Misc_VirtualSize),
                           section_alignment)

    # CODE | EXECUTE | READ | WRITE
    characteristics = 0xE0000020
    # Tên của section có 8 byte
    print "Please enter your new section name:"
    ten =raw_input()
    name = "."+ten+ (4 * '\x00')

    # Tạo section
    # Đặt tên
    pe.set_bytes_at_offset(new_section_offset, name)
    print "\t[+] Section Name = %s" % name
    # Đặt virtual size
    pe.set_dword_at_offset(new_section_offset + 8, virtual_size)
    print "\t[+] Virtual Size = %s" % hex(virtual_size)
    # Đặt virtual offset
    pe.set_dword_at_offset(new_section_offset + 12, virtual_offset)
    print "\t[+] Virtual Offset = %s" % hex(virtual_offset)
    # Đặt raw size
    pe.set_dword_at_offset(new_section_offset + 16, raw_size)
    print "\t[+] Raw Size = %s" % hex(raw_size)
    # Đặt raw offset
    pe.set_dword_at_offset(new_section_offset + 20, raw_offset)
    print "\t[+] Raw Offset = %s" % hex(raw_offset)
    # Đặt các trường còn lại thành 0
    pe.set_bytes_at_offset(new_section_offset + 24, (12 * '\x00'))
    # Đặt characteristics
    pe.set_dword_at_offset(new_section_offset + 36, characteristics)
    print "\t[+] Characteristics = %s\n" % hex(characteristics)

    # Bước 3 - Thay đổi header chính'
    print "[*] STEP 03 - Modify the Main Headers"
    #tăng NumberOfSection vì ta thêm 1 section mới
    pe.FILE_HEADER.NumberOfSections += 1
    print "\t[+] Number of Sections = %s" % pe.FILE_HEADER.NumberOfSections
    #SizeOfImage trong OPTIONAL_HEADER phải bằng VirtualAddress + VirtualSize (kích thước của header mới))
    pe.OPTIONAL_HEADER.SizeOfImage = virtual_size + virtual_offset
    print "\t[+] Size of Image = %d bytes" % pe.OPTIONAL_HEADER.SizeOfImage

    pe.write(exe_path)
#hàm xóa section
def delete(exe_path):
 pe=pefile.PE(exe_path)
 #in ra kích thước hiện tại của file pe trước khi xóa section.
 size = os.path.getsize(exe_path)
 print "\t[+]  Size before deleting = %d" % size
 #lấy vị trí của section ở cuối file để xóa.
 index=len(pe.sections)-1 
# có thể chọn index là 1 vị trí section bất kì nào để xóa, tuy nhiên cách dễ nhất không ảnh hưởng tới chức năng của file
# là ta sẽ xóa section được thêm vào cuối.

# Kiểm tra xem vị trí index có vượt quá section list không nếu đặt index là 1 vị trí bất kì
#nếu tồn tại index thì xóa.
 if (pe.FILE_HEADER.NumberOfSections > index and pe.FILE_HEADER.NumberOfSections == len(pe.sections)):
    print (pe.FILE_HEADER.NumberOfSections)
    # Xóa dữ liệu của section khỏi file.
    if pe.sections[index].SizeOfRawData != 0:
            pe.__data__ = pe.__data__[:-pe.sections[index].SizeOfRawData]
            pe.__data__ = (pe.__data__[:pe.sections[index].PointerToRawData] 
+                                    pe.__data__[pe.sections[index].PointerToRawData 
+                                                        pe.sections[index].SizeOfRawData:])  
    # Đặt các trường trong section table thành các byte rỗng.
    pe.sections[index].Name = '\x00'*8
    pe.sections[index].Misc_VirtualSize = 0x00000000
    pe.sections[index].VirtualAddress = 0x00000000
    pe.sections[index].SizeOfRawData = 0x00000000
    pe.sections[index].PointerToRawData = 0x00000000
    pe.sections[index].PointerToRelocations = 0x00000000
    pe.sections[index].PointerToLinenumbers = 0x00000000
    pe.sections[index].NumberOfRelocations = 0x0000
    pe.sections[index].NumberOfLinenumbers = 0x0000
    pe.sections[index].Characteristics = 0x00000000
    #Giảm NumberOfSection vì ta xóa 1 section đi
    pe.FILE_HEADER.NumberOfSections -= 1
    #ghi lại các thông tin vừa chỉnh sửa xuống file pe muốn xóa theo đường dẫn cung cấp.
    pe.write(exe_path)
    #in ra kích thước ban đầu của file pe sau khi đã xóa section.
    original_size = os.path.getsize(exe_path)
    print "\t[+] Original Size = %d" % original_size
 else:
        print "There's no section to remove."
        return;
 return;
def main():
   #lựa chọn hành động thêm hoặc xóa 1 section
    print "Enter 1 or 0 for adding or deleting a section: "
    select=int(input())
    #lấy đường dẫn của file pe.
    exe_path = R"D:\Source\add\putty.exe"
    
    if(select):
        add(exe_path)#thêm mới 1 section ở cuối file
    else: delete(exe_path)#mặc định là xóa section ở cuối file
if __name__ == '__main__': 
    main()
