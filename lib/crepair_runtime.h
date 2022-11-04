//
// Created by nikhil on 12/11/2019.
//

#ifndef CREPAIR_RUNTIME_H
#define CREPAIR_RUNTIME_H


#define CREPAIR_OUTPUT(id, typestr, value) \
  __crepair_output(id, typestr, value);


int __crepair_choice(char* lid, char* typestr,
                    int* rvals, char** rvals_ids, int rvals_size,
                    int** lvals, char** lvals_ids, int lvals_size);

int __crepair_output(char* id, char* typestr, int value);


#endif //CREPAIR_RUNTIME_H
