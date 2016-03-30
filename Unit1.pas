unit Unit1;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, XPMan, jpeg, ExtCtrls;

type
  TForm1 = class(TForm)
    peFilePathEdit: TEdit;
    sectionFilePathEdit: TEdit;
    peFileSelectBtn: TButton;
    sectionFileSelectBtn: TButton;
    lbl1: TLabel;
    lbl2: TLabel;
    xpmnfst1: TXPManifest;
    grp1: TGroupBox;
    secWriteCB: TCheckBox;
    secReadCB: TCheckBox;
    secExecCB: TCheckBox;
    backupCB: TCheckBox;
    changeEntryPointCB: TCheckBox;
    entryPointEdit: TEdit;
    stripOverlayCB: TCheckBox;
    doneBtn: TButton;
    dlgOpen1: TOpenDialog;
    secNameEdit: TEdit;
    lbl4: TLabel;
    codeSecCB: TCheckBox;
    initDataSec: TCheckBox;
    uninitDataSecCB: TCheckBox;
    secCantBeCachedCB: TCheckBox;
    nonPageableSecCB: TCheckBox;
    sharedSecCB: TCheckBox;
    img1: TImage;
    procedure peFileSelectBtnClick(Sender: TObject);
    procedure sectionFileSelectBtnClick(Sender: TObject);
    procedure doneBtnClick(Sender: TObject);
    function alignToValue(size: DWORD; baseSize: DWORD):DWORD;
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

//===================================================
//
// On select pe file button click
//
//===================================================
procedure TForm1.peFileSelectBtnClick(Sender: TObject);
begin
  dlgOpen1.Filter := 'Executable Files (*.exe)|*.EXE';
  if dlgOpen1.Execute then peFilePathEdit.Text := dlgOpen1.FileName;
end;


//===================================================
//
// On select section file button click
//
//===================================================
procedure TForm1.sectionFileSelectBtnClick(Sender: TObject);
begin
  dlgOpen1.Filter := 'All Files (*.*)|*.*';
  if dlgOpen1.Execute then sectionFilePathEdit.Text := dlgOpen1.FileName;
end;


//===================================================
//
// Aligns a value
//
//===================================================
function TForm1.alignToValue(size: DWORD; baseSize: DWORD):DWORD;
begin
  if size mod baseSize = 0 then Result := size
  else Result := ((size div baseSize) + 1) * baseSize;
end;  

//===================================================
//
// On done button click
//
//===================================================
procedure TForm1.doneBtnClick(Sender: TObject);
var
  hPE, hSecFile, hMap: THandle;
  base, secFileContents: Pointer;
  peFileName, secFileName: PChar;
  pImage_dos_header: ^IMAGE_DOS_HEADER;
  pImage_nt_headers: ^IMAGE_NT_HEADERS;
  pImage_section_header, newSectionHeader: ^IMAGE_SECTION_HEADER;
  noOfSections: Word;
  fileAlignment, sectionAlignment, actualSecFileSize, alignedSecFileSize, secCharacteristics, temp: DWORD;
  backupFileName: array[0..MAX_PATH] of Char;
  newSectionName: array[1..8] of Char;

begin

  // Validate both files
  peFileName :=  PChar(peFilePathEdit.Text);
  secFileName := PChar(sectionFilePathEdit.Text);

  if (StrLen(peFileName) = 0) or (StrLen(secFileName) = 0) then Exit;

  //Create backup
  if backupCB.Checked then
  begin
      StrCat(@backupFileName, peFileName);
      StrCat(@backupFileName, '.bak');
      if CopyFileA(peFileName, @backupFileName, True) = False then
      begin
        MessageDlg('Cannot create backup\nCheck if the file already exists' +#13+ 'Aborting', mtError, [mbOK], 0);
        Exit;
      end;
  end;

  hPE := CreateFileA(peFileName, GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
  if hPE = INVALID_HANDLE_VALUE then
  begin
    MessageDlg('Cannot open the PE file' +#13+ 'Check if the file is read-only', mtError, [mbOK], 0);
    Exit;
  end;

  hSecFile := CreateFileA(secFileName, GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
  if hSecFile = INVALID_HANDLE_VALUE then
  begin
    MessageDlg('Cannot open the section file' +#13+ 'Check if the file is read-only', mtError, [mbOK], 0);
    CloseHandle(hPE);
    Exit;
  end;

  hMap := CreateFileMappingA(hPE, 0, PAGE_READWRITE, 0, 0, 0);
  if hMap = 0 then
  begin
    MessageDlg('Cannot open create the mapping object', mtError, [mbOK], 0);
    CloseHandle(hPE);
    CloseHandle(hSecFile);
    Exit;
  end;

  base := MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, 0);
  if Integer(base) = 0 then
  begin
    MessageDlg('Cannot open map view of file', mtError, [mbOK], 0);
    CloseHandle(hMap);
    CloseHandle(hPE);
    CloseHandle(hSecFile);
    Exit;
  end;

  pImage_dos_header := base;
  if StrLComp(Pointer(pImage_dos_header), 'MZ', 2) <> 0 then
  begin
    MessageDlg('Not a valid PE file.\nMZ header missing', mtError, [mbOK], 0);
    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hPE);
    CloseHandle(hSecFile);
    Exit;
  end;

  pImage_nt_headers := Pointer(Integer(base) + pImage_dos_header^._lfanew);
  if StrLComp(Pointer(pImage_nt_headers), 'PE'+#0#0, 4) <> 0 then
  begin
    MessageDlg('Not a valid PE file.\nPE header missing', mtError, [mbOK], 0);
    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hPE);
    CloseHandle(hSecFile);
    Exit;
  end;

  //At this point we can safely assume that the files are valid and successfully opened
  noOfSections :=  pImage_nt_headers^.FileHeader.NumberOfSections;
  fileAlignment := pImage_nt_headers^.OptionalHeader.FileAlignment;
  sectionAlignment := pImage_nt_headers^.OptionalHeader.SectionAlignment;

  actualSecFileSize := GetFileSize(hSecFile, 0);
  alignedSecFileSize := alignToValue(actualSecFileSize, fileAlignment);
  
  secFileContents := AllocMem(alignedSecFileSize);
  ReadFile(hSecFile, secFileContents^, actualSecFileSize, temp, 0);
  CloseHandle(hSecFile);    //We no longer need it anymore

  Inc(pImage_nt_headers^.FileHeader.NumberOfSections);  //Increase section count
  pImage_section_header :=  Pointer(Integer(pImage_nt_headers) + SizeOf(IMAGE_NT_HEADERS));

  newSectionHeader := Pointer(Integer(pImage_section_header) + (noOfSections * SizeOf(IMAGE_SECTION_HEADER)));
  pImage_section_header := Pointer(Integer(newSectionHeader) - SizeOf(IMAGE_SECTION_HEADER));
  ZeroMemory(newSectionHeader, SizeOf(IMAGE_SECTION_HEADER));

  secCharacteristics := 0;
  if codeSecCB.Checked then secCharacteristics := secCharacteristics or IMAGE_SCN_CNT_CODE;
  if initDataSec.Checked then secCharacteristics := secCharacteristics or IMAGE_SCN_CNT_INITIALIZED_DATA;
  if uninitDataSecCB.Checked then secCharacteristics := secCharacteristics or IMAGE_SCN_CNT_UNINITIALIZED_DATA;
  if secCantBeCachedCB.Checked then secCharacteristics := secCharacteristics or IMAGE_SCN_MEM_NOT_CACHED;
  if sharedSecCB.Checked then secCharacteristics := secCharacteristics or IMAGE_SCN_MEM_SHARED;
  if nonPageableSecCB.Checked then secCharacteristics := secCharacteristics or IMAGE_SCN_MEM_NOT_PAGED;
  if secExecCB.Checked then secCharacteristics := secCharacteristics or IMAGE_SCN_MEM_EXECUTE;
  if secReadCB.Checked then secCharacteristics := secCharacteristics or IMAGE_SCN_MEM_READ;
  if secWriteCB.Checked then secCharacteristics := secCharacteristics or IMAGE_SCN_MEM_WRITE;


  //Set new section name
  ZeroMemory(@newSectionName, SizeOf(newSectionName));
  StrCopy(@newSectionName, PChar(secNameEdit.Text));
  CopyMemory(@(newSectionHeader^.Name), @newSectionName, 8);

  with newSectionHeader^ do
  begin
    Misc.VirtualSize := actualSecFileSize;
    VirtualAddress := pImage_section_header^.VirtualAddress + alignToValue(pImage_section_header^.Misc.VirtualSize, sectionAlignment);
    PointerToRawData := pImage_section_header^.PointerToRawData + pImage_section_header^.SizeOfRawData;
    SizeOfRawData := alignedSecFileSize;
    Characteristics := secCharacteristics;
  end;

  //Increase size of image
  Inc(pImage_nt_headers^.OptionalHeader.SizeOfImage, alignToValue(actualSecFileSize, sectionAlignment));

  //Close Mapping object
  UnmapViewOfFile(base);
  CloseHandle(hMap);

  //Now Append section data
  SetFilePointer(hPE, 0, 0, FILE_END);
  WriteFile(hPE, secFileContents^, alignedSecFileSize, temp, 0);
  FreeMem(secFileContents);
  CloseHandle(hPE);  
  MessageDlg('New section successfully added!',  mtInformation, [mbOK], 0);
end;


end.
