#include "u2f_app_i.h"

// Generated scene handler on_enter functions
#define ADD_SCENE(prefix, name, id) void prefix##_scene_##name##_on_enter(void*);
#include "u2f_scene_config.h"
#undef ADD_SCENE

// Generated scene handler on_event functions
#define ADD_SCENE(prefix, name, id) \
    bool prefix##_scene_##name##_on_event(void*, SceneManagerEvent);
#include "u2f_scene_config.h"
#undef ADD_SCENE

// Generated scene handler on_exit functions
#define ADD_SCENE(prefix, name, id) void prefix##_scene_##name##_on_exit(void*);
#include "u2f_scene_config.h"
#undef ADD_SCENE

// Generated scene list  
void (*const u2f_scene_on_enter_handlers[])(void*) = {
#define ADD_SCENE(prefix, name, id) prefix##_scene_##name##_on_enter,
#include "u2f_scene_config.h"
#undef ADD_SCENE
};

bool (*const u2f_scene_on_event_handlers[])(void*, SceneManagerEvent) = {
#define ADD_SCENE(prefix, name, id) prefix##_scene_##name##_on_event,
#include "u2f_scene_config.h"
#undef ADD_SCENE
};

void (*const u2f_scene_on_exit_handlers[])(void*) = {
#define ADD_SCENE(prefix, name, id) prefix##_scene_##name##_on_exit,
#include "u2f_scene_config.h"
#undef ADD_SCENE
};

const SceneManagerHandlers u2f_scene_handlers = {
    .on_enter_handlers = u2f_scene_on_enter_handlers,
    .on_event_handlers = u2f_scene_on_event_handlers,
    .on_exit_handlers = u2f_scene_on_exit_handlers,
    .scene_num = U2fSceneNum,
};
