#pragma once

#include "idp.hpp"
#include "loader.hpp"

#include "cxxgen1.h"

class rust_plugmod_t : public plugmod_t {
public:
    rust::Box<PlugMod> inner;

    rust_plugmod_t(rust::Box<PlugMod> pm) : inner(std::move(pm)) {}

    virtual bool idaapi run(size_t arg) override {
        return inner->run(arg);
    }

    virtual ~rust_plugmod_t() {
        inner->term();
    }
};

plugmod_t* idalib_create_plugmod(rust::Box<PlugMod> pm) {
    return new rust_plugmod_t(std::move(pm));
}
