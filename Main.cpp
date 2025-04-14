
// Function API use commenter plug-i
#include "stdafx.h"
#include <WaitBoxEx.h>
#include <set>
#include <list>
#include <vector>

#define MYTAG "#API: "

static const char SITE_URL[] = { "https://github.com/kweatherman/IDA_WhatAPIs_PlugIn/" };

struct ltstr
{
	bool operator() (const std::string &a, const std::string &b) const
	{
		return stricmp(a.c_str(), b.c_str()) < 0;
	}
};
std::set<std::string, ltstr> apiSet;

// Import segment bounds tracking
struct BOUNDS
{
	ea_t startEA, endEA;
};
static std::vector<BOUNDS> impsBndTable;
static UINT32 commentCount = 0;

static void processFunction(func_t *f);

// Main dialog
static const char mainDialog[] =
{
	"BUTTON YES* Continue\n" // "Continue" instead of "okay"
	"WhatAPIs\n"

    #ifdef _DEBUG
    "** DEBUG BUILD **\n"
    #endif
	"Adds function API usage list comments to each function that has them.\n\n"
    "Version %Aby Sirmabus\n"
    "<#Click to open site.#WhatAPIs Gtihub:k:1:1::>\n\n"

    " \n\n\n\n\n"
};

// Initialize
static plugmod_t* idaapi init()
{
	return PLUGIN_OK;
}

void idaapi term()
{
}

static void idaapi doHyperlink(int button_code, form_actions_t &fa) { open_url(SITE_URL); }

// Import module name enumeration callback
static int idaapi importNameCallback(ea_t ea, const char *name, uval_t ord, void *param)
{
	// Keep named ones, skip ordinals
	if(name)
		apiSet.insert(name);	
	return 1;
}

// Plug-in process
bool idaapi run(size_t arg)
{
	qstring version;
	msg("\n>> WhatAPIs: v: %s, built: %s\n", GetVersionString(MY_VERSION, version).c_str(), __DATE__);

    try
    {
        if (!auto_is_ok())
        {
            msg("** Must wait for IDA to finish processing before starting plug-in! **\n*** Aborted ***\n\n");
            goto exit;
        }
       
		commentCount = 0;
        apiSet.clear();
		impsBndTable.clear();
		plat.Configure();

        // Show UI        
        int uiResult = ask_form(mainDialog, version.c_str(), doHyperlink);
        if (!uiResult)
        {
            msg(" - Canceled -\n");
            goto exit;
        }

        WaitBox::show();
        TIMESTAMP startTime = GetTimeStamp();

        // Build import segment bounds table
		// Most Windows executables have just one ".idata" imports segment, but can have two or more.
        msg("Gathering import segments:\n");           
        for (int i = 0; i < get_segm_qty(); i++)
        {
            if (segment_t *seg = getnseg(i))
            {
                if (seg->type == SEG_XTRN)
                {
					qstring name;
					if (get_segm_name(&name, seg) < 1)
						name = "????";

					msg(" \"%s\" %llX - %llX\n", name.c_str(), seg->start_ea, seg->end_ea);                      
                    impsBndTable.push_back({ seg->start_ea, seg->end_ea });                        
                }
            }
        }    		

		if (impsBndTable.empty())
		{
			msg("** No import segments located! **\n*** Aborted ***\n\n");
			goto exit;
		}

		// Ensure address ascending sorted
		std::sort(impsBndTable.begin(), impsBndTable.end(), [](const BOUNDS& a, const BOUNDS& b) { return a.startEA < b.startEA; });

        // Make a list of all import names
        if (size_t moduleCount = get_import_module_qty())
        {                         
            for (size_t i = 0; i < moduleCount; i++)
                enum_import_names((int) i, importNameCallback);

            char buffer1[32], buffer2[32];
            msg("Parsed %s modules, with %s total imports.\n", NumberCommaString(moduleCount, buffer1), NumberCommaString(apiSet.size(), buffer2));
        }

		if (apiSet.empty())
		{
			msg("** No imports located! **\n*** Aborted ***\n\n");
			goto exit;
		}

        // Iterate through all functions..
        BOOL aborted = FALSE;
        UINT32 functionCount = (UINT32) get_func_qty();
        char buffer[32];
        msg("Processing %s functions:\n", NumberCommaString(functionCount, buffer));

		for (UINT32 i = 0; i < functionCount; i++)
		{
			processFunction(getn_func(i));

			if (i % 500)
			{
				if (WaitBox::isUpdateTime())
				{
					if (WaitBox::updateAndCancelCheck((int) (((float)i / (float) functionCount) * 100.0f)))
					{
						msg("* Aborted *\n");
						break;
					}
				}
			}
		}
        msg("Done. %s API comments added in %s.\n", NumberCommaString(commentCount, buffer), TimeString(GetTimeStamp() - startTime));                  
    }
    CATCH()

    exit:;   
    apiSet.clear();
	impsBndTable.clear();
	refresh_idaview_anyway();
	WaitBox::hide();
	return true;
}


// Address O(log n) lookup
static BOOL isInImportSeg(ea_t address)
{
	int left = 0;
	int right = (int) impsBndTable.size();

	while (left != (right - 1))
	{
		int mid = (left + (right - left) / 2);
		if (address <= impsBndTable[mid - 1].endEA)
			right = mid;
		else
		if (address >= impsBndTable[mid].startEA)
			left = mid;
		else
		{
			// Gap between regions
			return FALSE;
		}
	};

	const BOUNDS &bounds = impsBndTable[left];
	if ((address >= bounds.startEA) && (address <= bounds.endEA))
		return TRUE;

	// Below or above all regions
	return FALSE;
}


static UINT32 getShortName(ea_t ea, LPSTR buffer, UINT32 bufferLen)
{
    qstring temp;
    UINT32 len = (UINT32) get_short_name(&temp, ea);
    if (len > 0)
    {
        if (len > bufferLen) len = bufferLen;
        memcpy(buffer, temp.c_str(), len);
        buffer[len] = 0;
    }
    else
        buffer[0] = 0;
    return(len);
}


// Process function
static void processFunction(func_t *func)
{
	// Skip tiny functions
	if(func->size() >= 5)
	{
		// Don't add comments to API wrappers
        char name[MAXNAMELEN];
        if (getShortName(func->start_ea, name, SIZESTR(name)) > 0)
        {
            if (apiSet.find(name) != apiSet.end())
                return;
        }

		// Iterate function body
		std::set<std::string> strSet;
		qstring comment, current;

        func_item_iterator_t it(func);
		do
		{
            ea_t currentEA = it.current();

			// Will be a "to" xref
			xrefblk_t xb;
			if(xb.first_from(currentEA, XREF_FAR))
			{
				BOOL isImpFunc = FALSE;
                name[0] = 0;

				// If in import segment
				// ============================================================================================
				ea_t refAdrEa = xb.to;
				if(isInImportSeg(refAdrEa))
				{
					flags64_t flags = get_flags(refAdrEa);
                    if (has_name(flags) && has_xref(flags) && plat.isEa(flags))
					{                        
                        if (getShortName(refAdrEa, name, SIZESTR(name)) > 0)
						{                           
							// Nix the imp prefix if there is one
							if(strncmp(name, "__imp_", SIZESTR("__imp_")) == 0)
								memmove(name, name + SIZESTR("__imp_"), ((strlen(name) - SIZESTR("__imp_")) + 1));

							isImpFunc = TRUE;
						}
						else
							msg("%llX *** Failed to get import name! ***\n", refAdrEa);
					}
				}
				// Else, check for import wrapper
				// ============================================================================================
				else				
				{
					// Reference is a function entry?
					flags64_t flags = get_flags(refAdrEa);
					if(is_code(flags) && has_name(flags) && has_xref(flags))
					{
						if(func_t *refFuncPtr = get_func(refAdrEa))
						{
							if(refFuncPtr->start_ea == refAdrEa)
							{                             
                                if (getShortName(refAdrEa, name, SIZESTR(name)) > 0)
								{                                 
									// Skip common unwanted types "sub_.." or "unknown_libname_.."
									if(
										// not "sub_..
										/*"sub_"*/ (*((PUINT) name) != 0x5F627573) &&

										// not "unknown_libname_..
										/*"unknown_"*/ ((*((PUINT64) name) != 0x5F6E776F6E6B6E75) && (*((PUINT64) (name + 8)) != /*"libname_"*/ 0x5F656D616E62696C)) &&

										// not nullsub_..
										/*"nullsub_"*/ (*((PUINT64) name) != 0x5F6275736C6C756E)
										)
									{
										// Nix the import prefixes
										if(strncmp(name, "__imp_", SIZESTR("__imp_")) == 0)
											memmove(name, name + SIZESTR("__imp_"), ((strlen(name) - SIZESTR("__imp_")) + 1));

										// Assumed to be a wrapped import if it's in the list
										isImpFunc = (apiSet.find(name) != apiSet.end());
									}
								}
								else
									msg("%llX *** Failed to get function name! ***\n", refAdrEa);
							}
						}
					}
				}

				// Found import function to add list
				if(isImpFunc)
				{
					// Skip the large common STL names
					if(strncmp(name, "std::", SIZESTR("std::")) != 0)
					{
						// Skip if already seen in this function						
						if(strSet.find(name) == strSet.end())
						{							
                            // Append to existing comments w/line feed
							strSet.insert(name);
                            if(comment.empty() && current.empty())
                            {								                                
                                if(get_func_cmt(&current, func, true) < 1)
                                    get_func_cmt(&current, func, false);

                                if(!current.empty())
                                {					
									comment = current;                        			
									comment += "\n" MYTAG;
                                }
                            }

                            if(comment.empty())
								comment += MYTAG;

							// Append a "..." (continuation) and bail out if name hits max comment length
							if((comment.size() + strlen(name) + SIZESTR("()") + sizeof(", ")) >= (MAXSTR - sizeof("...")))
							{
								comment += " ...";
								break;
							}
							// Append this function name
							else
							{
								if(strSet.size() != 1)
									comment += ", ";
								comment += name; comment += "()";
							}
						}
					}
					else
					{
						//msg("%s\n", szName);
					}
				}
			}

		} while(it.next_addr());

		if(!strSet.empty() && !comment.empty())
		{
            // Add comment            
			set_func_cmt(func, comment.c_str(), true);
			commentCount++;
		}
	}
}


// ============================================================================
const static char plugin_name[] = "Function API Usage Commenter";
__declspec(dllexport) plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_UNL,
    init,
    term,
    run,
    plugin_name,
    plugin_name,
    plugin_name,
    NULL
};
