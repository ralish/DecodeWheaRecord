Changelog
=========

v0.5.0
------

- Improved error handling decoding `WHEA_ERROR_RECORD` structures (thanks @Romboter!)
- Improved decoding support for `WHEA_XPF_MCA_SECTION` errors records & added test case
- Added a Changelog and backfilled it with details on all prior releases
- Another large batch of code quality & tooling improvements
- Add tests for memory error sections
- Updated NuGet dependencies

v0.4.3
------

- Improve tolerance of unexpected structure sizes for memory error records

v0.4.2
------

- Add support for .NET 8 as a build target (thanks @reynoldskr!)
- Several code quality & tooling improvements
- Updated NuGet dependencies

v0.4.1
------

- Fix bug in `WHEA_MEMORY_ERROR_EXT_SECTION_INTEL` error decoder
- Add test for `WHEA_MEMORY_ERROR_EXT_SECTION_INTEL` error record

v0.4.0
------

- Giant update to supported errors and events
- Bumped .NET target framework from v4.6.2 to v4.7.2
- Another batch of code quality & tooling improvements
- Overhauled docs & added reverse engineering notes
- Add several more tests
- Updated NuGet dependencies

v0.3.0
------

- Add support for many additional WHEA error sections & structures
- Don't treat unexpected `WHEA_REVISION` version as fatal
- Add Windows SDK v10.0.26100 reference and custom headers
- Huge number of code quality & tooling improvements
- Updated NuGet dependencies

v0.2.0
------

- Add support for the large majority of WHEA events
- Add support for `WHEA_FIRMWARE_ERROR_RECORD_REFERENCE`
- Add initial minimal test project (thanks @kirhgoph!)
- Add several test cases for various WHEA events
- Huge number of code quality & tooling improvements
- Updated NuGet dependencies

v0.1.0
------

- Initial stable release
