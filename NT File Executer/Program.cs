// See https://aka.ms/new-console-template for more information


using NT_File_Reader;
using System.CommandLine;

Argument<FileInfo> Argfile = new Argument<FileInfo>("file")
{
    Description = "File to read"
};
RootCommand rootCommand = new("NT Program Executer");
rootCommand.Arguments.Add(Argfile);
rootCommand.SetAction(parseResult =>
{
    FileInfo? parsedFile = parseResult.GetValue(Argfile);
    RunFile(parsedFile!.FullName);
    return 0;
});
ParseResult parseResult = rootCommand.Parse(args);
return parseResult.Invoke();

static unsafe void RunFile(string FileName)
{
    Extentions.RunExecuteable(FileName);
}
