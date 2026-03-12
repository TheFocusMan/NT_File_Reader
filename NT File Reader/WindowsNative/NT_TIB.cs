using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace NT_File_Reader.WindowsNative
{
    [StructLayout(LayoutKind.Sequential)]
    public struct NT_TIB
    {
        public IntPtr ExceptionList;    // מצביע לרשימת ה-SEH (Structured Exception Handling)
        public IntPtr StackBase;        // כתובת הבסיס של המחסנית (הקצה הגבוה)
        public IntPtr StackLimit;       // גבול המחסנית (הקצה הנמוך)
        public IntPtr SubSystemTib;     // מידע עבור תת-מערכות (לרוב NULL)

        // איחוד (Union) בין FiberData ל-Version
        public IntPtr FiberData;

        public IntPtr ArbitraryUserPointer; // מקום פנוי לשימוש המשתמש/אפליקציה
        public IntPtr Self;             // מצביע לכתובת ההתחלה של ה-TIB עצמו
    }
}
