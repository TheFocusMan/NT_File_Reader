using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace System.Reflection.PortableExecutable
{
    [StructLayout(LayoutKind.Sequential)]
    public struct ResourceDirectory
    {
        public uint Characteristics;      // מאפיינים (כרגע 0)
        public uint TimeDateStamp;       // חותמת זמן של המשאב
        public ushort MajorVersion;      // גרסה ראשית
        public ushort MinorVersion;      // גרסה משנית
        public ushort NumberOfNamedEntries; // מספר הכניסות המזוהות לפי שם
        public ushort NumberOfIdEntries;    // מספר הכניסות המזוהות לפי ID
    }

    [StructLayout(LayoutKind.Explicit, Size = 8)]
    public struct ResourceDirectoryEntry
    {
        // --- 4 בתים ראשונים: זיהוי (שם או מזהה) ---
        [FieldOffset(0)] public uint Name;          // RVA למחרוזת (אם הביט הגבוה דלוק)
        [FieldOffset(0)] public ushort Id;          // מזהה מספרי (אם הביט הגבוה כבוי)

        // --- 4 בתים אחרונים: כתובת היעד ---
        [FieldOffset(4)] public uint OffsetToData;  // מצביע ל-DataEntry או Directory

        // תכונות עזר (Helper Properties) לזיהוי סוג הכניסה
        public bool NameIsString => (Name & 0x80000000) != 0;
        public bool DataIsDirectory => (OffsetToData & 0x80000000) != 0;

        // ניקוי הביט הגבוה לקבלת ה-Offset האמיתי (ביחס לתחילת סקציית ה-Resource)
        public uint Offset => OffsetToData & 0x7FFFFFFF;
        public uint NameOffset => Name & 0x7FFFFFFF;
    }
}
