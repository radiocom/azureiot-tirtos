// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include "azure_c_shared_utility/lock.h"
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/xlogging.h"

#include <ti/sysbios/BIOS.h>
#include <ti/sysbios/knl/Clock.h>
#include <ti/sysbios/knl/Task.h>
#include <ti/sysbios/knl/Semaphore.h>

DEFINE_ENUM_STRINGS(LOCK_RESULT, LOCK_RESULT_VALUES);

typedef struct TIRTOS_Semaphore_TAG
{
	Semaphore_Params semParams;
	Semaphore_Struct semStruct;
	Semaphore_Handle semHandle;
} TIRTOS_Semaphore;

/*Tests_SRS_LOCK_99_002:[ This API on success will return a valid lock handle which should be a non NULL value]*/
LOCK_HANDLE Lock_Init(void)
{
	TIRTOS_Semaphore* lock_mtx = (TIRTOS_Semaphore*)malloc(sizeof(TIRTOS_Semaphore));
	Semaphore_Params_init(&lock_mtx->semParams);
	Semaphore_construct(&lock_mtx->semStruct, 1, &lock_mtx->semParams);
	lock_mtx->semHandle = Semaphore_handle(&lock_mtx->semStruct);
    return (LOCK_HANDLE)lock_mtx;
}


LOCK_RESULT Lock(LOCK_HANDLE handle)
{
    LOCK_RESULT result;
    if (handle == NULL)
    {
        /*Tests_SRS_LOCK_99_007:[ This API on NULL handle passed returns LOCK_ERROR]*/
        result = LOCK_ERROR;
        LogError("(result = %s)", ENUM_TO_STRING(LOCK_RESULT, result));
    }
    else
    {
    	TIRTOS_Semaphore* lock_mtx = (TIRTOS_Semaphore*)handle;
    	Semaphore_pend(lock_mtx->semHandle, BIOS_WAIT_FOREVER);
        result = LOCK_OK;
    }
    return result;
}
LOCK_RESULT Unlock(LOCK_HANDLE handle)
{
    LOCK_RESULT result;
    if (handle == NULL)
    {
        /*Tests_SRS_LOCK_99_011:[ This API on NULL handle passed returns LOCK_ERROR]*/
        result = LOCK_ERROR;
        LogError("(result = %s)", ENUM_TO_STRING(LOCK_RESULT, result));
    }
    else
    {
    	TIRTOS_Semaphore* lock_mtx = (TIRTOS_Semaphore*)handle;
        Semaphore_post(lock_mtx->semHandle);
        result = LOCK_OK;
    }
    return result;
}

LOCK_RESULT Lock_Deinit(LOCK_HANDLE handle)
{
    LOCK_RESULT result=LOCK_OK ;
    if (NULL == handle)
    {
        /*Tests_SRS_LOCK_99_013:[ This API on NULL handle passed returns LOCK_ERROR]*/
        result = LOCK_ERROR;
        LogError("(result = %s)", ENUM_TO_STRING(LOCK_RESULT, result));
    }
    else
    {
        /*Tests_SRS_LOCK_99_012:[ This API frees the memory pointed by handle]*/
    	TIRTOS_Semaphore* lock_mtx = (TIRTOS_Semaphore*)handle;
        free(lock_mtx);
    }
    
    return result;
}
